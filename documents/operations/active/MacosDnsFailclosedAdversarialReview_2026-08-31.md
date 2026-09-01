# macOS DNS Fail-Closed Enforcement — Adversarial Security Review (2026-08-31)

Scope: the M1 DnsFailclosed posture for macOS — per-service `networksetup` loopback
pinning, the pf `:53` floor, the startup-recovery guard, and the backup/restore
document — as implemented in `crates/rustynetd/src/macos_dns_sc_protect.rs`,
`phase10.rs` (`MacosCommandSystem`), `macos_dns_failclosed.rs` (the QH-39
verifier), `macos_blind_exit.rs`, `privileged_helper.rs`, and the daemon startup
path. Design lineage: `MacosDnsFailclosedEnforcementGap_2026-08-28.md`.

Stance: adversarial. The worst outcome this review hunts is FAIL-OPEN (the host
resolves off-mesh while the posture claims it cannot); the second is
FALSE-CLOSED (the operator's real DNS is stranded with no recovery path).
Every finding below carries a CONFIRMED / REFUTED / PARTIAL verdict with
file:line evidence from this tree. Confidence is deliberately under-claimed
where the evidence is code-reading rather than a live repro.

---

## Executive summary

No FAIL-OPEN path was confirmed. The pf `:53` floor is ordered correctly for
every knob combination audited (§3), the apply order puts the filter before the
resolver mutation (§4), the privileged argv boundary is an exact, exhaustive
allowlist (§5), and both `assert_dns_protection` and the shipped verifier fail
closed on unreadable state rather than vacuously passing (§2, §6). The
enforcement is wired for the exit role (and blind exit), not just anchor/client
(§7).

Three CONFIRMED weaknesses were found, ranked by severity:

1. **S1 — Posture drift on hot-plugged services is never re-detected (bounded
   leak window: unbounded in time).** The pinned service set is enumerated once
   at apply; the per-service re-enumerating assert runs only inside a generation
   apply, and the reconcile loop applies a new generation only on
   membership/assignment/failure changes — never on a service-set change. A
   service enabled after apply (Wi-Fi toggle, USB/Thunderbolt ethernet, VPN
   service) stays un-pinned indefinitely, in contrast to the code comment that
   claims the reconcile loop keeps surfacing the drift. Practical leak is
   bounded by the pf floor (plaintext :53 off-tunnel is still dropped), so the
   exposure is the divergence itself plus non-:53 resolution channels
   (DoH/:443, :5353), not a plaintext :53 hole. (§1)

2. **S6 — The shipped `macos-dns-failclosed-check` verifier is much narrower
   than the posture it certifies.** It reads exactly two observations
   (`/etc/resolv.conf` nameservers and the scutil *primary unscoped* resolver)
   and never queries pf or the per-service pinning, so a green verdict is
   compatible with every gap in §1 and §2. It is honest in the fail-closed
   direction (missing/empty/unreadable inputs fail), but "overall_ok" must not
   be read as "closed"; the doc-adjacent tooling that treats it as the posture
   oracle over-trusts it. (§6)

3. **S4 — A crash mid-pin-loop can leave partial SC residue the startup guard
   cannot see.** The guard's loopback test reads only the scutil primary
   (resolver #1) unscoped nameservers. If a crash interrupts the pin loop after
   secondary services were pinned but before the primary-service's pin landed,
   the primary still shows the operator's real DNS, the guard decides
   `NoAction`, and the pinned secondaries carry invisible loopback residue.
   Recovery currently depends on a later successful generation apply rather
   than the guard. A different (and distinct from the already-fixed backup
   loopback-residue edge) partial state. (§4)

A FALSE-CLOSED (stranding) weakness was **not** confirmed: teardown ordering,
the failed-restore hold, the retained backup, and the loud startup refusal all
behave as designed on the paths audited, with two under-claimed residual notes
in §4.

---

## §1 Hot-plug / TOCTOU service set — CONFIRMED (drift undetected; leak pf-bounded)

**Mechanism.** `apply_dns_protection` enumerates enabled services once
(`phase10.rs:4585`, via `enumerate_networksetup_services`, `phase10.rs:4191`)
and pins exactly that set. `assert_dns_protection` *does* re-enumerate the live
service list and fails on any service that is un-pinned or non-loopback
(`phase10.rs:4713-4731`) — so the drift *detector* exists. The question is
cadence, and the cadence is absent:

- The only production call sites of `assert_dns_protection` are inside
  `apply_generation_stages`, immediately after `apply_dns_protection`
  (`phase10.rs:6766-6770`). `grep` over `daemon.rs` finds **zero** invocations
  of `assert_dns_protection` / `assert_killswitch` outside the apply path.
- The reconcile loop re-applies a generation only when `will_apply_generation`
  is true: controller state `FailClosed`, `RestrictionMode::Recoverable`,
  `assignment_changed`, `membership_changed`, or `local_route_reconcile_pending`
  (`daemon.rs:10321-10325`, applied at `daemon.rs:10440-10490` with
  `protected_dns: true` at `daemon.rs:10464`). A network service being enabled
  or disabled on the host changes **none** of these.
- The reconcile cadence itself is 1 s (`DEFAULT_RECONCILE_INTERVAL_MS`,
  `daemon.rs:484`) with a 5-failure cap (`daemon.rs:522`) — the loop is hot
  every second and simply never re-checks DNS posture on a healthy node.

**Consequence.** A comment inside the apply failure path claims "the reconcile
loop's `assert_dns_protection` keeps surfacing the drift" (`phase10.rs:4579-
4583`). On this tree that claim is not implemented: on a healthy node the
assert never runs again after the apply that established the generation. The
drift persists until some unrelated event (membership epoch bump, assignment
watermark change, a failure) triggers a re-apply — potentially forever.

**Leak analysis (why this is bounded, not catastrophic).** A hot-plugged
service carries its own DNS (typically DHCP-learned, e.g. 192.168.1.1) and is
un-pinned. The pf killswitch anchor, however, is interface-agnostic for the
DNS block: `block drop out quick inet proto {udp,tcp} to any port 53` renders
with no interface qualifier (`phase10.rs:3451-3459`), and the only :53 passes
are tunnel-scoped (`phase10.rs:3443-3450`). So the new service's plaintext DNS
egress is dropped by pf regardless of the SC drift; what leaks is (a) the
*advertised* posture (mDNSResponder knows real resolvers and may answer some
queries from cache/paths the anchor does not cover), (b) DNS over non-:53
channels — DoH/:443 by applications, mDNS :5353 — which the :53 floor never
covered, and (c) the QH-39 oracle divergence (see §6), which weakens
verification-based evidence until the next re-apply.

**Fix direction.** Give the reconcile tick a posture probe that does not
require a generation apply: a periodic (or SCDynamicStore-change-triggered)
call of `assert_dns_protection` whose failure either (a) schedules a
re-apply/re-pin directly, or (b) promotes the controller to the recoverable
restriction state, which the existing `will_apply_generation` disjunct
(`daemon.rs:10321-10322`) already converts into a full re-apply. The drift
detector already exists; only the trigger is missing. Fixing the stale comment
at `phase10.rs:4579-4583` should land with it.

---

## §2 Listener-absent fail-closed assumption — PARTIAL (core sound; side doors under-claimed)

**Sound core.** After pinning, every enabled service advertises exactly
`127.0.0.1` (`-setdnsservers` replaces the service's entire server list — the
apply writes a single-element argv, `macos_dns_sc_protect.rs:136-143`; the
assert rejects any service with a non-loopback *or empty* list,
`phase10.rs:4718-4731`). Nothing binds :53 on loopback on macOS by design — the
rustynet resolver binds `127.0.0.1:53535` (`linux_dns_protect.rs:179-198`) and
the OS reaches it only through the scoped resolver file
`/etc/resolver/rustynet` (`nameserver 127.0.0.1` + `port 53535`,
`linux_dns_protect.rs:190-198, 368-390`), scoped to the `rustynet` domain
only. A query to a pinned service's resolver therefore hits a dead loopback
port and the resolver set contains no fall-back candidate: there is no
secondary real server the pin "didn't clear", because `-setdnsservers`
replaces the list wholesale. Resolution of non-mesh names fails closed.

**Side doors that remain (under-claimed, code-level):**

- **Pre-existing `/etc/resolver/<domain>` files.** macOS honors per-domain
  resolver files *ahead of* the service-level DNS, and the enforcement never
  enumerates `/etc/resolver/` — it manages only its own
  `/etc/resolver/rustynet` (`linux_dns_protect.rs:179, 320-321, 368-390`). An
  operator's pre-existing `/etc/resolver/example.com` pointing at a real
  nameserver survives enforcement untouched. The pf floor keeps :53 to that
  nameserver blocked, so the classic plaintext case stays fail-closed; a
  resolver file naming a DoT (:853) or DoH (:443) endpoint bypasses both the
  pin and the floor. Neither the assert nor the verifier (§6) observes these
  files. Fix direction: enumerate `/etc/resolver/*` at apply/assert and either
  refuse to arm protection over foreign files or fail the assert on any file
  the daemon does not own.
- **Scoped / supplemental SC resolvers.** The per-service
  `-getdnsservers` read (`phase10.rs:4208-4228`) observes the service's plain
  server list, not the scoped-query or supplemental-matching sections that
  `scutil --dns` also exposes — and the verifier deliberately skips the entire
  scoped section (`macos_dns_failclosed.rs:152-158`). After a full pin these
  sections should mirror loopback, but nothing *asserts* that, and a VPN- or
  profile-supplied supplemental matcher is exactly the kind of state a future
  macOS release could repopulate. Under-claimed: not confirmed exploitable,
  unobserved by any enforcement point.
- **Search domains are not cleared.** `-setdnsservers` does not touch
  `SearchDomains`; a stale search domain can still route bare names into
  mDNS/Bonjour (see next item). Benign for :53 but widens the .local door.
- **mDNS :5353.** `.local`/Bonjour resolution is multicast on :5353 and is
  outside the :53 floor by design. Hosts on the LAN observe the Mac's mDNS
  queries regardless of posture. Out of M1's stated scope; recorded here so
  the boundary is explicit.
- **Resolver cache.** Entries cached by mDNSResponder before the pin survive
  for their TTL. Transient (seconds), inherent to any SC-level switch, not
  actionable beyond documentation.

---

## §3 pf floor ordering / coverage — REFUTED (sound across audited combinations)

The §7 2026-08-29 pf-parity claims in the Gap doc were re-derived from the
renderer itself, not taken from the doc. Non-strict, `dns_protected=true`
render order in `render_macos_killswitch_pf_rules` (`phase10.rs:3421-3506`):

1. `set block-policy drop` (`:3429`), 2. `pass quick on lo0 all` (`:3436`),
3. tunnel-scoped `pass out quick … inet proto {udp,tcp} to any port 53 keep
state` (`:3443-3450`), 4. interface-agnostic `block drop out quick inet proto
{udp,tcp} to any port 53` (`:3451-3459`), 5. tunnel-wide `pass … inet all`
(`:3460-3462`) and the optional egress-interface pass (`:3463-3467`) — both
*after* the :53 blocks, so neither re-opens LAN DNS, 6. SSH CIDR passes
(`:3481-3494`, tcp/22 only), 7. STUN/endpoint UDP passes (`:3496-3505`), 8.
optional `block drop out quick inet6 all` (`:3503`), 9. the unconditional
terminal `block drop out quick all` (`:3505-3506`).

- **IPv4 :53 off-tunnel:** blocked by rule 4 before any broad pass. ✅
- **IPv6 :53:** there is no inet6 :53 pass anywhere in the render. With
  `ipv6_blocked=false` it falls to the terminal block (`:3505`); with
  `ipv6_blocked=true` it hits the explicit v6 block (`:3503`) first. Either
  way fail-closed. ✅ (The Gap doc's "v6 parity via default-deny floor" claim
  holds.)
- **Strict fail-closed:** renders *no* DNS rules at all (the whole
  `!strict_fail_closed` block is skipped, `:3439-3467`) — tunnel :53 included
  — leaving only lo0 + terminal block. Closed. ✅
- **Blind exit:** `render_pf_rules` routes to the blind-exit builder whenever
  the blind config is present (`phase10.rs:3660-3666`). That builder renders
  the same tunnel-scoped :53 pass / labeled :53 block pair when
  `config.dns_protected` (`macos_blind_exit.rs:85-110`) *before* the
  tunnel-wide pass (`:113-115`) and before the mesh-CIDR-scoped egress passes
  (`:123-127`), and ends in its own unconditional terminal block
  (`:133`). Its live-eval side (`evaluate_macos_blind_exit_pf_rules`,
  `macos_blind_exit.rs:160-256`) explicitly flags any interface-wide quick
  pass above the terminal block and validates the :53 pair when
  `dns_protected` is set (`:243-256`). ✅
- **Generator↔verifier pairing:** `ruleset_contains_dns_rule`
  (`phase10.rs:3717-3750`) accepts both rendered and pfctl-normalized
  (`port = 53`) forms, and the knob-combination pin test
  `macos_render_pf_rules_dns_pass_is_tunnel_scoped_for_every_knob_combination`
  exists at `phase10.rs:16593`. The §7 parity claim is verified for this tree.

**Two hardening notes (not CONFIRMED weaknesses):**

- The endpoint passes (`:3496-3505`) take operator-configured
  `traversal_stun_servers` (`daemon.rs:11377`) with no port-53 exclusion. An
  operator who configures a "STUN" server on :53 pokes a UDP-:53 hole for that
  IP on the egress interface. Operator-supplied, single-IP, UDP-only; a
  validation `port != 53` (or a doc warning) would close it cheaply.
- `pass quick on lo0 all` (`:3436`) means any local process that binds
  loopback :53 is a trusted resolver by definition. This is the local-trust
  model working as intended, recorded so it is a decision, not an oversight.

---

## §4 Apply/teardown races and crash windows — PARTIAL (one confirmed gap; ordering sound)

**Apply ordering is the safe direction.** `apply_dns_protection` sets
`dns_protected = true` *first* (`phase10.rs:4558`) so the very first pf render
carries the DNS-block rules, then installs pf, and only then mutates SC
(enumerate → capture → backup write → per-service pin,
`phase10.rs:4559-4646`). The window between pf-apply and pin is
"advertised-real-DNS but :53-filtered" — resolution outage, never leak. The
reverse order (pin first) would strand resolution with no filter; it does not
occur anywhere. The backup is written before the first mutation
(`phase10.rs:4626-4632`), so a mid-pin crash always leaves a readable backup
covering *at least* everything about to be pinned.

**Failure unwind holds closed.** `StageMarker::DnsApplied` is pushed only
after apply *and* assert succeed (`phase10.rs:6766-6770`), so a failed apply
never records the stage; the `RollbackIntent::FailClosed` arm deliberately
holds DNS applied through a failed-apply unwind (`phase10.rs:6920-6931`) and
`force_fail_closed` blocks all egress. A partial pin (failure at service k of
n) leaves k pinned + pf block-all + a full backup; the next successful
generation apply re-captures (loopback services resolve their baseline from
the retained prior backup, `macos_dns_sc_protect.rs:373-400`) and re-pins —
self-healing.

**Teardown ordering is the safe direction.** `rollback_dns_protection` sets
`dns_protected = false`, then restores every backed-up service **before** the
pf anchor reload that drops the :53 blocks (`phase10.rs:4733-4762`); a failed
SC restore returns *without* reloading the anchor and *without* deleting the
backup (`phase10.rs:4748-4750`; `restore_networksetup_dns_from_backup`
retains the file on any per-service failure, `phase10.rs:4228-4275`). The
no-backup restore path re-enumerates and fails loud only if services are
actually still pinned (`phase10.rs:4250-4270`). Shutdown-side, the
`CleanShutdown` intent runs the same rollback (`phase10.rs:6923-6927`).

**Startup guard truth table.** `decide_startup_recovery`
(`macos_dns_sc_protect.rs:508-521`) is complete over its three booleans and
the wiring refuses startup on the loud branch (`daemon.rs:11589-11595` →
`DaemonError::InvalidConfig`), before any runtime construction. The
`NoAction`/protection-running arm is fed a hardcoded `false`
(`macos_dns_sc_protect.rs:566`), which is correct for "before any protection
is applied in this process".

**CONFIRMED gap — partial-pin state invisible to the guard.** The guard's
`sc_dns_is_loopback` input is derived from `read_scutil_dns()` →
`parse_scutil_primary_resolver_nameservers()` → resolver #1 of the *unscoped*
section only (`macos_dns_sc_protect.rs:556-563`; `macos_dns_failclosed.rs:145-181`). Crash at pin-loop position k: if the service that
backs the primary resolver was already pinned, the guard sees loopback and
restores; if it was *not yet* pinned (services are pinned in enumeration
order, and the primary service is usually — but not guaranteed — first), the
primary still shows real DNS, the guard decides `NoAction`
(`macos_dns_sc_protect.rs:513-515`), and services 1..k carry loopback residue
with no automatic or loud recovery. Real-world impact is mitigated: after a
reboot pf is clear, the unpinned primary still resolves, and the next
successful daemon apply re-pins everything (healing the residue); the residue
becomes *persistent* only when the daemon starts but cannot complete a
protection apply (e.g. privileged helper unavailable). Fix direction: make
the guard observe all enabled services (the same
enumerate + `-getdnsservers` loop the rollback path already uses at
`phase10.rs:4250-4265`) instead of scutil resolver #1, or treat "any service
loopback + no protection running" as residue.

**Under-claimed residuals (no failure constructed):**

- A second daemon instance starting while a first is protecting would observe
  loopback + `dns_protection_running=false` + readable backup, restore the
  operator DNS, and delete the backup out from under the live instance
  (`macos_dns_sc_protect.rs:566, 632`). The window is fail-closed (the first
  instance's pf anchor persists and its next reconcile-generation apply
  re-captures and re-pins), but whether the daemon's single-instance
  guarantees make this unreachable was not verified in this pass.
- The guard trusts `read_scutil_dns()` returning `None` ⇒ "no residue
  evidence" (`macos_dns_sc_protect.rs:560-563`). Deliberate and documented,
  but it means a *broken* scutil plus loopback residue is silently not
  recovered (the daemon proceeds; the apply path's own capture guard then
  refuses on the loopback baseline without a prior entry —
  `macos_dns_sc_protect.rs:397-399` — so the strand surfaces loudly at apply
  time instead).

---

## §5 Privileged argv boundary — REFUTED (sound), one accepted-capability note

`validate_networksetup_args` (`privileged_helper.rs:2925-2947`) is an
exhaustive array-pattern match: `-listallnetworkservices` exactly;
`-getdnsservers <svc>` with the name validator;
`-setdnsservers <svc> <servers…>` with non-empty servers, valid name, and
servers either exactly `["Empty"]` or an all-parseable-IP list
(`macos_dns_sc_protect.rs:94-115`). There is no prefix or substring
acceptance — a verb that is not one of the three exact forms falls to the
catch-all `_ => Err` (`:2945-2947`). The name validator rejects empty,
>128-byte, and any control-character-bearing name (`:94-104`), so a
host-derived service name cannot smuggle a second argument or forge output;
the enumeration parser additionally aborts the *whole* apply on any single
invalid line (`:266-270`). The same validator is enforced on the helper-less
direct path (`phase10.rs:3616-3636`, the RN-19 symmetry gate), and the
`DnsFailclosedFile` builtin carries no caller-supplied path or content at all
— only a fixed selector from a closed set (`privileged_helper.rs:246-252,
290-291`; `linux_dns_protect.rs:296-321`).

**Accepted-capability note (not a break):** the allowlist deliberately permits
`-setdnsservers <svc> <arbitrary valid IPs>` — required for the exact-list
restore, and asserted as allowed in the boundary test
(`privileged_helper.rs:6113`). A daemon compromised at its own privilege level
can therefore point host DNS at attacker-chosen servers without ever touching
a code path bug. This is equivalent to the power the daemon already has
(refusing to pin at all) and stays bounded by the pf floor for :53, but it
belongs in the threat model as a granted capability of the M1 surface, not an
accident. The test name `…_permits_only_the_m1_surface`
(`privileged_helper.rs:6105`) slightly oversells the restriction: the M1
*mutation* surface is loopback/Empty; the restore form is broader by design.

---

## §6 Verifier honesty — CONFIRMED (oracle narrower than the posture it is cited for)

`macos-dns-failclosed-check` (module `macos_dns_failclosed.rs`, wired as
`rustynetd`'s `DnsFailclosed` probe, `vm_lab/mod.rs` `DaemonProbeOp::DnsFailclosed`)
evaluates exactly two observations
(`evaluate_macos_dns_failclosed_snapshot`, `macos_dns_failclosed.rs:83-108`):

1. `/etc/resolv.conf` present, with every `nameserver` entry loopback (empty
   or missing file fails — good).
2. `scutil --dns` **primary unscoped resolver (#1) nameservers all loopback**
   (`parse_scutil_primary_resolver_nameservers`, `:145-181`; advertisement
   predicate `:184-192`).

It never queries pf (no `pfctl` anywhere in the module), never reads
`networksetup -getdnsservers`, skips the entire scoped-queries section
(`:152-158`), and ignores `/etc/resolver/*` apart from the resolver's own
effects. Consequently `overall_ok=true` is fully compatible with: the §1
hot-plug drift (a low-priority new service's real DNS sits in the scoped
section, invisible), a flushed/absent pf anchor, foreign per-domain resolver
files, and any supplemental-resolver state. The fail-closed *direction* is
sound — unreadable scutil ⇒ `loopback_resolver_advertised=false` ⇒ fail
(`:234-243, 101-107`), and the scutil observation is a genuine independent
second opinion against a stale-but-loopback `resolv.conf` (`:184-192`) — but
the *coverage* is a two-point sample of a four-layer posture.

**Why this matters:** lab evidence and the orchestrator's `DnsFailclosed`
probe treat `overall_ok` as the DNS fail-closed verdict for the node. Green
should mean closed; here green means "primary resolver loopback and
resolv.conf cosmetic file loopback". The per-service truth is only observable
via the in-process `assert_dns_protection` (§1), which the verifier does not
duplicate and which does not run on a schedule.

**Fix direction:** extend the snapshot with (a) a per-service
`networksetup -getdnsservers` loop (the verifier runs with sufficient
privilege in the lab harness to read, if not write), (b) a pf
`-a <anchor> -s rules` presence check for the labeled
`rustynet-dns-block-lan-{udp,tcp}` rules (the label constants already exist
for exactly this pairing, `macos_blind_exit.rs:101-109`), and (c) an
`/etc/resolver/` foreign-file listing. Until then, any doc or tooling that
calls the check "the" DNS fail-closed oracle should be qualified.

---

## §7 Role applicability — REFUTED concern (enforcement is wired for the exit role)

The enforcement is not anchor/client-only; on macOS it arms for every role:

- `ApplyOptions.protected_dns` is unconditionally `true` at both production
  apply sites — bootstrap (`daemon.rs:8778`) and reconcile (`daemon.rs:10464`)
  — for client, anchor, relay, regular exit, and blind exit alike.
- The regular exit additionally applies DNS protection *inline* inside
  `apply_nat_forwarding` so the :53 blocks exist before NAT activation
  completes (`phase10.rs:4506-4511`).
- Blind exit forces `serve_exit_node = true` (`daemon.rs:8740-8741`), takes
  the blind branch of `apply_nat_forwarding` (`phase10.rs:4479-4493`), and —
  because `protected_dns` is still true — the subsequent
  `apply_dns_protection` at `phase10.rs:6767` sets `dns_protected`, which the
  blind-exit runtime config mirrors into the render
  (`phase10.rs:3699-3715`), so the blind anchor carries the :53 pass/block
  pair (`macos_blind_exit.rs:85-110`) and the SC pinning proceeds identically.

The exit-vs-anchor behavioral split (what the exit role *does* with protected
DNS once armed, e.g. LAN-query handling behind the NAT anchor) is the
companion investigation's territory (edit-1788259527134) and is intentionally
not re-derived here; this review only establishes that the M1 enforcement —
pf rules + SC pinning + assert + backup — is installed for the exit role and
is not gated on role anywhere in the apply path.

---

## Sound vs. unaudited — explicit statement

**Sound (audited on this tree, code-level):** pf floor ordering and IPv6
parity for all audited knob combinations including the blind-exit builder
(§3); apply/teardown ordering and the failed-restore hold (§4); backup
write-before-mutate and the loopback-residue capture guard (§4); the
privileged argv allowlist and its symmetry across both execution paths (§5);
the verifier's fail-closed handling of unreadable inputs (§6); role wiring of
the enforcement (§7).

**Confirmed weaknesses:** S1 drift never re-detected on a healthy node
(bounded leak, unbounded window); S4 partial-pin startup-guard blindness;
S6 verifier coverage gap. None is a confirmed plaintext-:53 fail-open.

**NOT audited in this pass (explicitly out of scope or unverified):** live
macOS behavior of mDNSResponder under pinned-SC (all §2 behavioral claims
about resolution paths are code + documented-mechanism reasoning, not a live
repro); supplemental/scoped resolver repopulation by VPN profiles; whether a
daemon single-instance lock makes the §4 second-instance scenario unreachable;
the Linux and Windows DNS fail-closed arms; the exit-role DNS behavior proper
(deferred to the companion investigation); and any performance or flakiness
property of the 1 s reconcile loop.
