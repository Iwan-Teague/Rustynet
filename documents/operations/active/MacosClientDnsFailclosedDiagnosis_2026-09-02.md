# macOS Client DnsFailclosed Diagnosis — 2026-09-02

Status: ACTIVE diagnosis — complete as of 2026-09-02 (§8 lists the live probes that would
confirm the root-cause chain before the fix lands).

## 0. Scope and verdict (summary)

Plain mesh **client** node (`macos-utm-1`, role = client, `ExitMode::Off`) fails the live-lab
`validate_baseline_runtime` stage's `DnsFailclosed` verifier on macOS. This is a **real product
defect** on the apply path, not the lab-side enforce-refresh gap (that gap — "daemon does not
re-apply signed state after restart" — was fixed in commit `10e7532a`; this run's daemon logged
`signed state refresh completed (reason=command)` and still ended with an incomplete DNS posture).

The defect shape: `apply_dns_protection` on macOS pins networksetup services to loopback DNS but
leaves **two pillars of the fail-closed posture absent**: no pf DNS-block rules ever installed
(0 in all 656 samples), and the loopback resolver is never the scutil PRIMARY resolver (0 in all
656 samples). Result: services point at 127.0.0.1 while (a) nothing enforces the block floor and
(b) whether anything answers on loopback is unproven — a half-applied posture, which is the
exact state the posture invariant forbids.

Invariant (stated up front, enforced by the fix in §6): **DNS is EITHER fully protected
(loopback resolver up AND answering as scutil primary, all enabled services pinned to it, pf
DNS-block floor installed) OR untouched — never half.**

## 1. Primary evidence (guest sampler + daemon log, macos-utm-1)

Sampler: 2-second-interval guest sampler over the whole live-lab run; pf-rules/scutil series have
656 samples, networksetup series 33 samples, launchd-proc series 38 samples.

| Observation | Verbatim sampler result | Samples |
| --- | --- | --- |
| Daemon bootstrapped + refreshed without error | no `dataplane bootstrap apply failed` in daemon log; `signed state refresh completed (reason=command)` present | whole run |
| networksetup loopback pin applied | Ethernet DNS = `127.0.0.1` | 33/33 samples |
| Daemon under launchd | pid present | 38/38 samples |
| pf `com.rustynet` DNS-block anchor | **rules count = 0** | 0/656 samples — NEVER populated |
| scutil PRIMARY resolver (#1) nameserver | **never `127.0.0.1`** | 0/656 samples |

Node identity: plain mesh **client**, `ExitMode::Off`. Not an exit, not blind-exit, no tunnel-up
exit posture.

## 2. Verifier pass contract (crates/rustynetd/src/macos_dns_failclosed.rs)

`evaluate_macos_dns_failclosed_snapshot` (:159-205) returns drift reasons; `overall_ok` ⇔ drift
empty (`build_macos_dns_failclosed_report` :530-541). Every condition that must hold:

| # | Condition (file:line) | Sampler observation | Verdict |
| --- | --- | --- | --- |
| 1 | resolv_conf_present (:163) | /etc/resolv.conf exists (daemon-era macOS) | PASS (assumed; see §8 unknowns) |
| 2 | nameservers non-empty (:170) | unknown from sampler | UNKNOWN |
| 3 | loopback_resolver_advertised (:177) — scutil PRIMARY resolver #1 non-empty AND all loopback (:281-289, parsed only from unscoped `resolver #1` :242-272) | scutil primary NEVER 127.0.0.1 (0/656) | **FAIL** |
| 4 | every resolv.conf nameserver loopback (:137-154) | unknown from sampler | UNKNOWN |
| 5 | pf_block_rules_present (:185-191) — some rustynet-owned anchor (`com.apple/rustynet_g<N>` / `com.rustynet/` prefixes, :81-82) carries BOTH `DNS_BLOCK_LAN_UDP_RULE` + `DNS_BLOCK_LAN_TCP_RULE` as `block ... port 53` rules (:327-343) | pf-rules count = 0 in ALL 656 samples | **FAIL** |
| 6 | networksetup_readable (:193-198) | networksetup readable (pin visible) | PASS |
| 7 | zero unpinned_services (:199-203) — ALL enabled hardware services loopback-only; a service with NO servers counts UNPINNED (:489-492) | Ethernet pinned 33/33; other enabled services unmeasured | UNKNOWN (risk) |

Two certain FAIL branches (3, 5) + two unknowns. Both certain failures are **apply-side
absences**: no pf DNS-block rules were ever generated, and no loopback resolver is advertised as
the system primary. The verifier is functioning as specified (QH-39 anti-tautology design: it
reads live system state, not daemon self-report).

## 3. Apply path — `MacosCommandSystem::apply_dns_protection` (crates/rustynetd/src/phase10.rs)

The macOS apply sequence (`apply_dns_protection`, phase10.rs:4609-4740):

1. `self.dns_protected = true` (:4610), then `apply_pf_rules(false)` (:4611;
   `strict_fail_closed = false`). A pf load error resets `dns_protected` to false and returns
   `DnsApplyFailed` (:4612-4613), so pinning is never reached when pf fails. A
   SystemConfiguration failure deliberately leaves `dns_protected` true (:4615-4636 comment:
   reverting would make the next reconcile re-render pf WITHOUT DNS-block rules; the S1
   re-assert cadence schedules one re-apply via `dns_posture_reassert_pending`).
2. M1 pinning: enumerate enabled services (:4637); the M1 capture guard refuses to proceed when
   the prior backup is unreadable (:4654-4664) and never records loopback residue as baseline
   (:4640-4649; see also macos_dns_sc_protect.rs:425); backup is written BEFORE the first
   mutation (:4684-4687); then each service is pinned with
   `networksetup -setdnsservers <svc> 127.0.0.1` (:4688-4698); any failure → `DnsApplyFailed`.
3. Best-effort file posture: all-loopback `/etc/resolv.conf` via
   `PrivilegedCommandProgram::DnsFailclosedFile` (:4713-4720) and a scoped
   `/etc/resolver/rustynet` file pointing at loopback:53535 (:4733-4740). The comment at
   :4726-4728 is load-bearing: the daemon runs UNPRIVILEGED and cannot bind :53;
   `/etc/resolver/<domain>` is the only OS-honored route to the resolver's :53535 bind, and it
   is scoped to `*.rustynet` ONLY.

**What governs DNS-block rule emission.** The pf rules are rendered by
`render_macos_killswitch_pf_rules` (:3442+). DNS-block rules (pass out udp/tcp 53 on the tunnel
interface + `block drop out` udp/tcp 53 labeled `DNS_BLOCK_LAN_UDP_RULE` / `DNS_BLOCK_LAN_TCP_RULE`)
are emitted iff `!strict_fail_closed && spec.dns_protected` (:3458, :3462-3479). Emission does
NOT depend on exit_mode, tunnel interface presence, or mesh peers. `killswitch_spec`
(:3714-3726) copies `self.dns_protected` verbatim (:3718). `apply_pf_rules` (:3796-3854)
re-renders from `killswitch_spec()` into the anchor (`com.apple/rustynet_g<generation>` or
legacy `com.rustynet/`), loads it through the privileged helper, and — unlike the blind-exit
branch, which verifies the live anchor after load (:3845) — the killswitch branch performs NO
post-load live verification (:3852 just returns Ok).

**Verdict: defect, not intentional full-tunnel-only design.** An intentional "protected DNS is
exit-only" design would not pin services for a client; the code pins whenever
`apply_dns_protection` runs and simultaneously leaves the floor absent. The live evidence (pins
present 33/33, floor present 0/656) is exactly the half-state no code path should produce.

**Leading root-cause chain for the absent floor.** `dns_protected` is per-instance state, and a
freshly-constructed `MacosCommandSystem` has `dns_protected = false` (phase10.rs:9554 comment).
`apply_pf_rules` is re-invoked from several paths without any DNS context:
`apply_peer_endpoint_bypass_routes` (:4488, when the endpoint set changes and an anchor already
exists), `apply_firewall_killswitch` (:4496), and `apply_nat_forwarding`'s client/non-blind
branch (:4541 — loads the killswitch anchor BEFORE NAT; only the `serve_exit_node` branch calls
`apply_dns_protection`, at :4551). After a daemon restart — precisely the Gap A context, where
the refreshed daemon re-applies signed state — a fresh instance re-rendering the anchor from any
of these paths emits an anchor WITHOUT DNS-block rules while the networksetup pins persist
(networksetup is machine-persistent). Whether this run's daemon ever called
`apply_dns_protection` at all, or whether the observed pins are residue from a previous run
(the M1 guard at macos_dns_sc_protect.rs:425 shows residue from prior applies is a recognized
state), cannot be distinguished from the sampler and is listed as a live probe (§8). Both
variants converge on the same half-state.

## 4. Loopback resolver & scutil primary

The loopback resolver socket is started for every role: the daemon binds
`config.dns_resolver_bind_addr` unconditionally in its run-loop setup (daemon.rs:12209; default
`DEFAULT_DNS_RESOLVER_BIND_ADDR = "127.0.0.1:53535"`, daemon.rs:444; a second probe bind at
daemon.rs:11843). So for the plain mesh client the :53535 listener should EXIST. The platform
differences decide what that is worth:

- Linux: an nft redirect sends :53 traffic to the resolver's :53535 bind
  (linux_dns_protect.rs:20-24) — a pinned primary actually gets answered.
- Windows: the resolver bind is normalized to :53 (daemon.rs:13268-13281) — a pinned primary
  gets answered directly.
- macOS: there is NO :53 redirect, and the daemon cannot bind :53 unprivileged
  (phase10.rs:4726-4728). The only OS-honored route into the resolver is the scoped
  `/etc/resolver/rustynet` file (:4733-4740), which covers `*.rustynet` names only.

Consequence: on macOS the networksetup pin (`127.0.0.1`, port 53 implied) points the OS primary
resolver at a port where NOTHING LISTENS. Even if scutil advertised loopback as primary, general
(non-`*.rustynet`) queries would be sent to a dead port. The scoped resolver file never makes
loopback the PRIMARY resolver — it only adds a domain-scoped resolver entry.

Why the scutil PRIMARY never showed 127.0.0.1 while Ethernet was pinned (33/33) is not fully
determined by the sampler. Candidates: (a) the scutil primary service is not the pinned Ethernet
service (macOS picks the primary by service order + router reachability; the verifier reads the
unscoped `resolver #1` only — macos_dns_failclosed.rs:242-272); (b) the pin came from residue
applied under different interface conditions and the SC primary was derived from another
service; (c) mDNSResponder did not re-publish the pinned service as the unscoped primary. All
three require one live `scutil --dns` capture (§8). What IS established: `loopback_resolver_
advertised` was false, so verifier branch :177 legitimately failed; and on macOS the pin side
of the posture is hollow by construction — nothing answers the pinned port for general DNS.

## 5. Spec decision — does a plain mesh client REQUIRE protected DNS?

The controlling clauses are conditional on their face:

- Requirements.md:90 (verbatim): "DNS fail-close behavior must prevent DNS leakage outside
  Rustynet policy **when VPN mode requires protected DNS**."
- Requirements.md:186 (verbatim): "VPN operating modes **requiring protected routing** must fail
  closed for traffic and DNS on tunnel failure."

Both key on the mode requiring protected DNS/routing. A plain mesh client with `ExitMode::Off`
uses the tunnel for mesh-internal traffic only; it performs no protected general routing, so it
is NOT unconditionally a mode requiring protected DNS. Per the read-order precedence
(Requirements.md over SecurityMinimumBar.md) and the strictest-secure rule (§2 rules: choose the
strictest secure practical default and document the choice), the decision is:

**Decision.** Protected DNS on macOS is a property of modes that CLAIM it — full-tunnel/exit
postures, and any mode whose apply path pins services. A plain mesh client must be left
UNTOUCHED (no service pins, no resolv.conf rewrite, no half floor). Critically, the current
behavior cannot be defended as "client with protected DNS": the pin points general DNS at a port
nothing listens on (§4), so the posture BREAKS resolution instead of protecting it — it is not
a weakened control being removed, it is breakage being removed. Any mode that DOES pin must
complete the full posture (§6 invariant). The lab verifier must be role-scoped to match: for a
plain client, "untouched" is compliant and "pins present without the floor" is drift — the
half-state is drift under EVERY reading.

## 6. Chosen fix + offline-testable core

**Chosen: option B for the plain client, with the option-A invariant machinery for every mode
that pins** — the combination that never weakens a real control and never leaves a half-applied
posture:

- **R1 — invariant enforcement on the apply path.** `apply_dns_protection` (phase10.rs:4609)
  must never pin a service unless it can complete the full posture in fail-closed order: the
  loopback resolver verified bound AND answering (post-bind probe of
  `config.dns_resolver_bind_addr`), the pf DNS-block floor verified LIVE after load (wire
  `assert_killswitch` :4831-4885 / `assert_dns_protection` :4744-4788 into the killswitch
  branch of `apply_pf_rules`, closing the no-verification gap at :3852), services pinned, and
  the primary advertised loopback. Any incomplete step → restore the M1 backup
  (`rollback_dns_protection` :4790-4817 path) so the node ends UNTOUCHED, and return
  `DnsApplyFailed`. Pin-without-live-primary is today's fail-open/breakage shape and is
  forbidden.
- **R2 — no silent downgrade on re-render.** The re-render callers
  (`apply_peer_endpoint_bypass_routes` :4488, `apply_firewall_killswitch` :4496,
  `apply_nat_forwarding` client branch :4541) must not render a floor-less anchor while pinned
  services persist: detect live pins (`read_networksetup_dns_pin` :493-515) and either include
  the floor or refuse/repair by re-running the full `apply_dns_protection`. This kills the
  fresh-instance `dns_protected = false` clobber (phase10.rs:9554) that is the leading
  root-cause chain in §3.
- **R3 — plain client untouched + residue cleanup.** For a plain mesh client
  (`ExitMode::Off`, not `serve_exit_node`), apply paths must not pin; startup reconcile must
  detect leftover loopback pins (machine-persistent from a previous run) and restore them to
  the M1 baseline, ending untouched. Removing pin-to-dead-:53 from the client removes breakage,
  not a control (§5).
- **R4 — role-scoped lab stage.** `validate_baseline_runtime`'s macOS DnsFailclosed verifier is
  scoped by role: plain client → compliant when untouched, drift when pins exist without the
  full posture (half-state always drift); exit/full-tunnel → the full seven-condition contract
  of §2 unchanged.

**Offline-testable core** (pure functions / op-count, no live lab):

1. New pure decision fn, e.g. `macos_dns_posture_decision(resolver_answering: bool,
   pf_floor_live: bool, pins_present: bool) -> DnsPosture` with exactly two reachable
   outcomes — `FullyProtected` (all three true) and `Untouched` (pins absent; floor/pins must
   agree). No `Half` variant exists to construct. Unit tests: every incomplete combination →
   `Untouched` + "rollback required".
2. `render_macos_killswitch_pf_rules` (phase10.rs:3442): existing emission-iff-`dns_protected`
   test, plus NEW test — a render request with `pinned_services` non-empty and DNS-block
   emission suppressed is refused (R2), never silently rendered floor-less.
3. `DryRunSystem` op-count tests: `apply_dns_protection` issues pin operations ONLY after the
   resolver-verify operation succeeds; an incomplete posture yields restore operations (M1
   backup restore) and zero final pin operations; `apply_nat_forwarding` client branch with
   pre-existing pins does not emit a floor-less anchor load.
4. Verifier-scoping tests: plain-client snapshot with pins absent + floor absent →
   `overall_ok` (untouched compliant); any snapshot with pins present + floor absent → drift
   under both role scopes (half-state always drift).

**Live proof:** the rank-1-harvest macOS `DnsFailclosed` stage passing on the engine of record
after the fix — plain client untouched-and-compliant, exit node fully protected — with the row
verified in `documents/operations/live_lab_node_run_matrix.csv` and the stage's own report
artifact (per §10.9 row-is-not-proof rule).

## 7. Risks / collisions

- **Gap A (commit `10e7532a`, post-restart signed-state refresh).** R2/R3 live on the same
  post-restart reconcile path the Gap A fix exercises. Ordering matters: the refresh must
  complete BEFORE the posture decision, else the fresh instance judges a half-delivered state.
- **M1 DNS backup (`MacosDnsBackupRebootSurvivalPlan_2026-09-02.md`, implementation review
  same date).** R1/R3 use the M1 restore path. The residue guard
  (macos_dns_sc_protect.rs:425) refuses a new baseline when residue is present — R3's startup
  cleanup must run BEFORE any new backup capture, or the guard fails every apply after a
  crashed run.
- **S1 re-assert 30 s cadence (`MacosDnsFailclosedS1S4FixDesign_2026-08-31.md`).**
  `dns_posture_reassert_pending` re-applies protection; under R1 a re-assert of an incomplete
  posture must fail closed (restore-to-untouched), not loop pinning forever against a dead
  :53.
- **Exit-adapter A2 + exit DNS failclosed.** DNS-block label emission
  (`DNS_BLOCK_LAN_UDP_RULE` / `DNS_BLOCK_LAN_TCP_RULE`, shared with
  macos_exit_dns_failclosed.rs:700-701/:783-784) must keep the live exit proofs green; R2 only
  adds refusals, it does not change exit rendering.
- **Role-split investigation (`MacosExitDnsFailclosedRoleSplitInvestigation_2026-08-31.md`).**
  §5's decision must be reconciled with that document's conclusions before landing R4; if that
  investigation already decreed client-unprotected DNS, R3/R4 implement it; if it decreed
  client-protected, R1 completes the posture instead (the invariant machinery is identical —
  only the plain-client default flips).
- **Scope:** macOS-only. Linux (nft :53→:53535 redirect, linux_dns_protect.rs:20-24) and
  Windows (bind normalized to :53, daemon.rs:13268-13281) pin to a port that answers; nothing
  here changes them.

## 8. Unknowns / needs a live probe

1. `/etc/resolv.conf` contents during the run — verifier conditions #2 (nameservers non-empty)
   and #4 (all loopback) unmeasured by the sampler.
2. Full enabled networksetup service list + per-service DNS — condition #7
   (unpinned_services) risk unmeasured; only Ethernet observed.
3. Whether anything answered 127.0.0.1:53 on the guest (expected NO per §4; confirm with one
   `dig @127.0.0.1 -p 53` during a run).
4. Full `scutil --dns` capture: which service is the unscoped primary, and its relationship to
   the pinned Ethernet service (resolves §4 candidates a/b/c).
5. Whether THIS run invoked `apply_dns_protection` at all, or the 33/33 pins are prior-run
   residue: grep the run's daemon log for the pin/setdnsservers path, `DnsApplyFailed`, and
   DNS-posture markers.
6. Which re-render caller ran last (anchor generation observed in pfctl output) — pins down the
   exact clobber site among :4488/:4496/:4541.
7. SecurityMinimumBar.md DNS clauses were not re-read for this diagnosis; re-verify at fix
   time that no unconditional client-DNS control exists there before landing R3.
