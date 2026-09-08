# QH-78 wiring design — the fail-closed DNS posture floor (macOS)

**Status: DESIGN, decided. Implementation NOT started.**
**Owner decision in QH-78 (`QualityHardeningTodo_2026-07-25.md`, disposition 2026-09-08):** on
entering fail-closed, a node adopts the MORE RESTRICTIVE of the posture its live state computes
and the posture it last persisted as its intent — never the less restrictive. This document
designs the mechanism. All file:line citations were read from the tree on 2026-09-08.

## 1. The defect, grounded

`force_fail_closed` (`phase10.rs:8037`) clears `current_serve_exit_node` to `false` and
`current_exit_mode` to `ExitMode::Off`, runs `block_all_egress` (macOS:
`apply_pf_rules(true)`, the strict ruleset, `phase10.rs:5675`), and transitions to
`DataplaneState::FailClosed`. Any later `macos_dns_posture(Off, false)` therefore returns
`ScopedResolverOnly` (`phase10.rs:894`), even when the last *committed* generation applied
`FullyProtected`. On a rebooted node whose 120 s bundles are stale, `load_verified_trust`
fails every reconcile tick (`daemon.rs`, `reconcile` → `force_fail_closed_or_restrict` early
return) so no generation is ever applied again — the advertised posture stays
`scoped_resolver_only` until fresh bundles arrive. The persisted session snapshot still
carries the full-tunnel intent: `persist_state` (`daemon.rs:10302`) writes
`{timestamp_unix, peer_ids, selected_exit_node, lan_access_enabled}` and `restore_state`
(`daemon.rs:10399`) reloads `selected_exit_node` untouched.

The two `macos_dns_posture` call sites (`daemon.rs:8909` bootstrap, `daemon.rs:10651`
reconcile) only feed `apply_dataplane_generation`, and `apply_dataplane_generation` is the
apply path a stale-bundle node never reaches (it is reachable *from* `FailClosed`
(`phase10.rs:7529-7534` allows the recovery transition), but only once trust verifies again).
Wrapping those sites cannot fix the reboot case. `maybe_assert_dns_posture`
(`daemon.rs:10927`) is explicitly gated off while `FailClosed` or restricted, and it only
*asserts* — it schedules a re-apply through the generation path, which is exactly the path
that does not run. So closing QH-78 needs two things that do not exist today:

1. **P1 — a path that installs the protective DNS posture while fail-closed, with no
   committed generation**, and
2. **P2 — persistence of the last protective intent in a form the fail-closed path can
   read after a reboot.**

## 2. Decision

Build the floor as three pieces.

### 2.1 D-A: the intent record (P2)

**What:** a new module `crates/rustynetd/src/dns_intent.rs`, owning a durable sibling file of
the daemon state file: `<state_path>.dns-intent.json` (same derivation pattern as
`networksetup_dns_backup_path`, `macos_dns_sc_protect.rs:324`, and the QH-40 residue marker
suffix, `shutdown_residue.rs:36`).

Schema v1 (mirrors `ShutdownResidueMarker`, `shutdown_residue.rs:63-90`):

```
{ "schema_version": 1, "recorded_unix": u64, "platform": "macos",
  "node_id": String, "posture": "fully_protected" | "scoped_resolver_only" }
```

**When written — the single rule that makes this an intent and not a snapshot:** only after
`apply_dataplane_generation` returns `Ok` in the daemon's bootstrap and reconcile paths,
writing exactly `applied_dns_posture` (the value `macos_dns_posture` produced for the apply —
`daemon.rs:8906-8910`, `daemon.rs:10647-10653`). Never written by `force_fail_closed`, never
written by the floor install itself, never cleared on shutdown. Consequences:

- intent = "the posture of the last generation that actually committed";
- a **signed demotion** (membership bundle withdraws `selected_exit_node` →
  `daemon.rs:9407` clears it → next reconcile applies `ScopedResolverOnly` → Ok) rewrites the
  intent to the weaker posture and legitimately lowers the floor. The floor mechanism never
  needs to understand demotion — the normal apply path retires the stale intent for free;
- a failed apply writes nothing, so a node that *tried* to go full-tunnel and failed does not
  mint an intent for a posture it never had (fail-closed: no posture without an apply).

Reader API: `read_dns_intent(state_path) -> Option<DnsPosture>` on macOS plus a
`Corrupt` outcome folded to `Some(DnsPosture::FullyProtected)` at the read layer (see §4).
Write API: atomic temp+rename, `0600`, best-effort fsync of the parent directory.

**Why not extend `SessionStateSnapshot`:** the snapshot's four fields are parsed by
`linux_mesh_status` (`linux_mesh_status.rs:187`) and by the mesh-status freshness evaluator;
widening it couples a macOS DNS concept to a cross-platform, digest-bearing contract. The
sibling file follows two proven precedents (QH-40 residue marker, M1 networksetup backup) and
keeps the snapshot format frozen.

**Tamper posture, honestly:** the file is not signed — there is no local signing key for
per-node state, and the QH-40 marker set the precedent that durable local records are
presence+parse protected, not authenticated. The abuse directions are asymmetric and both
safe or mitigated: *corruption* reads as `FullyProtected` (restrictive-only); *deletion*
lowers the floor, so the floor ALSO consults `restore_state`'s `selected_exit_node`
(`daemon.rs:10399`) as a second, independent source: `selected_exit_node.is_some()` implies
`Some(FullyProtected)`. The floor is the max over both sources, so an attacker must delete
the intent file AND the session snapshot — the latter is the daemon's own state file, whose
absence is already a loud, operator-visible condition.

### 2.2 D-B: the fail-closed install path (P1)

**What:** a new `DataplaneSystem` trait method (beside
`apply_dns_protection_for_posture`, `phase10.rs:794`):

```rust
fn enforce_dns_posture_fail_closed(&mut self, posture: DnsPosture) -> Result<(), SystemError>;
```

`MacosCommandSystem` implementation — the M1 pin sequence *minus pf*:

1. `verify_loopback_resolver_live()` (`phase10.rs:4792`) — the A6 gate, unchanged: never pin
   at a resolver that is not answering. Loopback traffic passes the strict ruleset
   (`pass quick on lo0 all`), so the probe and the pins both work while fail-closed.
2. For `FullyProtected`: enumerate services; run the M1 **capture guard** against the prior
   backup (`read_networksetup_dns_backup`; present-but-unreadable prior backup refuses, loopback
   residue without a prior entry refuses — identical semantics to `apply_dns_protection`,
   `phase10.rs:5337-5357`); write the backup BEFORE the first mutation; pin every service to
   `127.0.0.1`; write resolv.conf and the scoped resolver file.
3. **Never calls `apply_pf_rules`** — not with `false`, not with `true`. The strict fail-closed
   ruleset `force_fail_closed` installed is the egress floor; replacing it with the
   non-strict DNS-protection anchor would be a fail-open (see §5, T-5). This is the one
   behavioral difference from `apply_dns_protection` (`phase10.rs:5301`), and it is why the
   method is new rather than a flag on the existing one.
4. Updates `self.dns_posture` / `self.dns_protected` fields to reflect what was installed so
   post-recovery asserts start from truth.
5. Idempotent: a second call with no drift performs no privileged mutation (observe, compare,
   skip).

`RuntimeSystem` records calls for tests (`phase10.rs:7015` has the pattern);
`DryRunSystem` returns `Ok` (`phase10.rs:1163`). Linux/Windows systems return an error — the
call site never invokes them (below), and an unexpected call failing loudly is the
fail-closed direction.

**Controller surface:** `Phase10Controller::enforce_fail_closed_dns_floor(&mut self, intent:
Option<DnsPosture>) -> Result<(), Phase10Error>` — computes
`current = macos_dns_posture(self.current_exit_mode, self.current_serve_exit_node)`, resolves
`target = fail_closed_dns_posture_floor(current, intent)`, and calls the system method only
when `target` differs from the system's live posture. This is **where the drafted pure
decision function plugs in**: `dns_posture_restrictiveness` (`Untouched 0,
ScopedResolverOnly 1, FullyProtected 2`) and
`fail_closed_dns_posture_floor(current, persisted_intent: Option<DnsPosture>) -> DnsPosture`
land in `phase10.rs` beside `macos_dns_posture` (`phase10.rs:894`), exactly as QH-78
specified — with `None` a no-op for every variant, a weaker intent never lowering the
current posture, and idempotence (`floor(floor(x, i), i) == floor(x, i)`). Its sole
production caller is `enforce_fail_closed_dns_floor`; it stops being dead code the moment
that caller exists.

**Daemon wiring — two call sites, both already fail-closed-gated:**

- **Entry:** inside `force_fail_closed_or_restrict` (`daemon.rs:11100`), after
  `controller.force_fail_closed` succeeds: read the intent (D-A), call
  `enforce_fail_closed_dns_floor`. Covers bootstrap and reconcile entry points alike (both
  route through this one function). A install failure here is *not* swallowed: it increments
  the same failure accounting and, at `max_reconcile_failures` consecutive failures,
  escalates via `restrict_permanent` (the existing ladder's terminal rung — the node is
  already dark; permanent restriction additionally survives trust recovery).
- **Drift:** at the top of each reconcile tick, when
  `controller.state() == DataplaneState::FailClosed`: re-run the floor enforce (idempotent).
  This heals external drift (a user or MDM resetting service DNS while the node is
  fail-closed) and re-installs after a restart-in-place. The QH-40 residue scan and the M1
  startup guard run earlier in `run_daemon` (`daemon.rs:11893-11966`) and are untouched.

**macOS-only:** the call sites guard on `cfg!(target_os = "macos")`, mirroring the
`applied_dns_posture` pattern. Other platforms compute and persist nothing new; their DNS
posture models are different (Linux resolv.conf, Windows NRPT) and are out of scope (§5).

### 2.3 D-C: interaction with the startup DNS recovery guard

The M1 guard (`daemon.rs:11919-11937` → `run_startup_dns_recovery`,
`macos_dns_sc_protect.rs:845`) treats loopback SC DNS observed at startup, while no
protection is running, as residue and restores the backup — or refuses startup loudly when it
cannot. The floor does not weaken it, and cannot race it:

- The guard runs **before** `DaemonRuntime` construction; the floor's first possible
  invocation is inside `force_fail_closed_or_restrict`, which only exists after the runtime
  is up. Order is structural, not conventional.
- A rebooted fail-closed node therefore goes: guard restores originals (backup consumed,
  retired after verify — `macos_dns_sc_protect.rs:944-958`) → daemon enters `FailClosed` on
  stale trust → floor re-pins under a *live* daemon whose resolver is bound and probed. The
  guard-to-floor window is availability-only: the strict pf ruleset blocks all egress
  including :53, so no query escapes to the LAN resolver in between (this is the same
  reasoning QH-78 records for why the downgrade was never a leak — the floor removes the
  dependence on that reasoning for the *advertised* posture but does not change the pf
  reality).
- The floor's backup write keeps the guard correct for the *next* boot: because the floor
  reuses the capture guard, a node that boots fail-closed, pins, and is then hard-killed
  leaves a backup whose baselines are pre-pin originals, so the next startup restore is
  exact. Skipping the backup on the floor path (the tempting shortcut) would strand the next
  boot — this invariant is pinned by test T-6 (§6).
- `protected_dns`: both production call sites hard-code `protected_dns: true`
  (`daemon.rs:8919`, `daemon.rs:10663`), and `Untouched` is reserved for the opt-out
  (`phase10.rs:872-874`). The floor is gated on the same controller `dns_protected()` state
  `maybe_assert_dns_posture` already consults (`daemon.rs:10938`); a node opted out of DNS
  protection never installs the floor. Since `floor` never returns `Untouched` for a
  protective input, the opt-out must be checked *before* consulting the floor, not inside it.

### 2.4 Restriction vs fail-closed scope

The rule is scoped to `DataplaneState::FailClosed` only. A *restricted* node that still
applies generations is governed by the normal apply path (which computes its own posture from
live state); extending the floor to restricted states would freeze a stale intent over a live,
signed, more recent decision — the opposite of what the owner decided. Restricted-but-not-
fail-closed keeps today's behavior.

## 3. Fail-closed analysis of every new input

| Input | Absent | Malformed | Stale | Set by the wrong party |
| --- | --- | --- | --- | --- |
| Intent file missing (first boot, pre-upgrade node) | `None` → floor is a no-op; posture = live-computed. Status quo, no behavior change. This is the correct zero-state: absence means "no committed protective intent ever", not "assume protective". | — | — | — |
| Intent file present, unreadable / bad JSON / wrong `schema_version` / wrong `platform` / wrong `node_id` | — | Read as **`Some(FullyProtected)`** + `log::error!` naming the path. Rationale: an unverifiable record cannot vouch for a weak posture; the wrong guess here must be restrictive-only. Mirrors QH-40's "a marker that exists but cannot be read counts as residue present" (`shutdown_residue.rs`, module doc). Availability cost: pins a plain client at loopback; security cost: none (pins only restrict). | — | Forged `fully_protected` by a local user: forces pins — restrictive-only; the strict ruleset already blocked egress anyway. Forged `scoped_resolver_only`: cannot *lower* anything — the floor is a max, and the live-computed posture stands as the other input. |
| Intent file stale (e.g. full-tunnel intent months old, node long demoted) | — | — | **Deliberately never expires.** Intent is the last *committed* posture; a signed demotion rewrites it at the next successful apply. Until then the floor holds the stronger posture — availability-only, conservative direction. | — |
| Both sources deleted (intent file + session snapshot) | Floor degrades to live-computed posture. Deleting the daemon's state file is an operator-visible teardown, not a silent act; documented residual risk, not solved here (§5). | — | — | — |
| `selected_exit_node` source | `None` → no contribution to the max. | Snapshot parse failure already fails the load (`restore_state` → `ResilienceError`) — pre-existing fail-closed, reused. | Same never-expires rule. | Snapshot is written only by the daemon at `0600`-equivalent state-dir perms; a forged `Some` forces pins (restrictive-only). |
| Floor install failure (probe dead, helper error, backup unreadable) | No pins written — the apply is all-or-nothing before the first mutation, same M2 contract as `apply_dns_protection` (`phase10.rs:5327-5335`). | Node stays strictly-pf fail-closed; posture stays live-computed; failure counted; `restrict_permanent` at the threshold. **Never** silently treated as installed. | — | — |
| `enforce_dns_posture_fail_closed` invoked on a non-macOS system | Returns `Err` (loud) — the call site's `cfg!` guard makes this unreachable; a future caller that removes the guard hits an error, not a no-op. | — | — | — |

The zero-effort path in every row is either the status quo (no floor mechanism engaged) or
the *more* restrictive posture. No row's default is permissive. This is the property the
recently-cut omittable-precondition proposal failed (omit → no check → proceed); here omit →
no floor → current posture unchanged, which is exactly the pre-QH-78 world and never a
downgrade *caused by the mechanism*.

## 4. What this does NOT solve

- **It does not make pf's strict ruleset redundant-safe.** The design removes the *advertised*
  downgrade; the two-mechanism agreement between pf and the pins is still only enforced
  incidentally. The FullyProtected *assert* (`phase10.rs:5476`, including
  `verify_live_pf_dns_floor`) still runs only through the generation path; a fail-closed node
  re-runs only the floor install, which pins but does not assert the (strict, different) pf
  ruleset. A pf regression *plus* a pins regression is still needed for a leak; this design
  narrows, but does not eliminate, that conjunction.
- **It does not restore connectivity.** A rebooted node with stale 120 s bundles stays
  dark until fresh bundles arrive. The floor changes what the node *advertises* about its
  DNS posture, nothing else.
- **It does not authenticate the intent record.** See §2.1 — no local signing key exists for
  per-node durable state. The residual risk (root deletes both sources) is accepted and
  documented, not engineered away here.
- **It does not give Linux or Windows an equivalent floor.** Linux loopback resolv.conf
  survives reboot in principle; there is no Linux startup DNS recovery guard and no Linux
  posture concept to floor. If a Linux analog of the downgrade exists, it is a separate
  finding, not covered by this design. **UNVERIFIED** — no Linux reboot-cell evidence was
  examined for this document.
- **It does not replace operator acknowledgement of the QH-40 residue marker**, and does not
  touch marker retirement (`daemon.rs:11938-11966`).

## 5. Test plan — each test names the mutation it catches

Repo precedent demanded by the brief: tests that still pass when the fix is reverted are
worthless. Each test below fails if the named mutation is made.

- **T-1** `fail_closed_dns_posture_floor` unit tests (`phase10.rs` test module): protective
  intent raises a weaker current; weaker intent never lowers; `None` no-op for all three
  variants; idempotence. *Catches:* inverting `max` to `min`, or `None → FullyProtected`
  default leaking into the pure function (the reader, not the function, owns that mapping).
- **T-2** intent-reader tests: absent → `None`; truncated JSON / unknown `schema_version` /
  wrong `platform` / wrong `node_id` → `Some(FullyProtected)`; `0o644` file →
  `Some(FullyProtected)`. *Catches:* a reader refactor that maps malformed → `None` (the
  permissive zero-effort path §3 forbids).
- **T-3** intent-write placement: apply Ok writes intent matching `applied_dns_posture`;
  apply Err writes nothing; `force_fail_closed` writes nothing. *Catches:* moving the write
  into `force_fail_closed` (minting intent for a posture never applied).
- **T-4** floor install is pf-silent: `RuntimeSystem` counts `apply_pf_rules` invocations
  across `enforce_fail_closed_dns_floor` and asserts zero. *Catches:* implementing the floor
  by reusing `apply_dns_protection` — which reloads the non-strict anchor
  (`phase10.rs:5309-5315`) and would downgrade the strict ruleset. **This is the
  fail-open mutation the whole design exists to prevent.**
- **T-5** idempotent per tick: two consecutive `enforce_fail_closed_dns_floor` calls with no
  drift issue zero privileged mutations (command-count assert). *Catches:* observe-compare-
  skip being replaced by unconditional reinstall (backup churn, helper load every tick).
- **T-6** floor writes the backup with pre-pin baselines: after floor install,
  `read_networksetup_dns_backup` shows non-loopback originals for every pinned service.
  *Catches:* skipping the capture guard on the floor path — which would make the NEXT boot's
  startup guard "restore" loopback pins (permanent strand; this is the M1 capture-guard
  defect class, `phase10.rs:5337`).
- **T-7** dead-resolver gate: `RuntimeSystem` with a closed loopback DNS port → floor returns
  `Err`, zero pins issued. *Catches:* dropping the A6 probe (`phase10.rs:4792`) from the new
  method — pinning at a dead :53535.
- **T-8** demotion lowers the floor: intent `fully_protected` → signed bundle withdraws
  exit → reconcile applies `ScopedResolverOnly` Ok → intent rewritten → subsequent
  `force_fail_closed` floor computes `ScopedResolverOnly` (no pins). *Catches:* a floor that
  reads the intent once and caches it (never retires a demoted intent — the "floor only
  ratchets up" bug).
- **T-9** escalation: N consecutive floor failures → `restrict_permanent` recorded.
  *Catches:* swallowing the install error (fail-closed node pretends the floor installed).
- **T-10** startup-guard interplay (unit, `run_startup_dns_recovery_with` injection seams):
  guard-restore-then-floor sequence leaves services pinned AND the backup retired; guard
  refusal (unreadable backup + loopback residue) still refuses startup even when an intent
  exists. *Catches:* floor running before the guard (fighting it over the same SC state) or
  an intent-present shortcut that skips the guard's refusal.
- **T-11 live-lab (the acceptance test this item was filed for):** the macOS reboot cell —
  full-tunnel node, reboot with stale bundles, node enters `FailClosed`. The
  `macos-dns-failclosed` verifier must report `fully_protected` while fail-closed. *Catches:*
  the entire wiring being absent (the exact evidence in run
  `state/live-lab-macos-reboot-20260907-050612` — verifier reporting `scoped_resolver_only`).

## 6. Effort

- **Mechanical (~1.5 d):** `dns_intent.rs` (schema, atomic 0600 write, reader + its T-2
  matrix); the two pure functions + T-1; the `DataplaneSystem` method signature +
  `MacosCommandSystem`/`RuntimeSystem`/`DryRunSystem` impls (the body is a reassembly of
  existing M1 helpers, not new privileged logic); the two daemon call sites; Linux/Windows
  trait stubs.
- **Judgement (~2 d):** the capture-guard/backups interaction under fail-closed (T-6) and
  confirming the resolver listener is bound before the first fail-closed tick (the A6 probe
  must never fire before `dns_resolver_bind_addr` is live — verify the bind ordering in the
  run loop during implementation); the escalation policy wiring (T-9); the guard-interplay
  test harness (T-10); the live-lab reboot cell re-run (T-11), which needs a full macOS lab
  cycle.

Total: **~3.5 days**, of which the live-lab proof is the long pole.

## 7. Owner decisions

- **D-1 (confirm, default chosen): unreadable intent ⇒ `FullyProtected`.** Converting
  corruption/tampering into forced pinning is restrictive-only but is a *policy* choice with
  an availability cost on a plain client. The design ships the strict mapping unless the
  owner prefers "unreadable ⇒ ignore + log", which reopens the permissive-default hole §3
  rejects. Recommend: keep the strict mapping.
- **D-2 (confirm, default chosen): escalation threshold** reuses `max_reconcile_failures`
  for consecutive floor-install failures rather than a new knob. Recommend: reuse — a new
  tunable is a second thing to fail stale.
- **D-3 (flag only): the two-sources-must-both-be-deleted residual.** Accepted here as
  documented risk; if the owner wants it closed, the follow-up is a digest of the intent
  file recorded inside the session snapshot (and vice versa), so deleting one is detectable
  from the other. Not designed, not estimated.
