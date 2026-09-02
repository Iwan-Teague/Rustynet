# macOS Client DnsFailclosed Diagnosis — 2026-09-02

Status: ACTIVE diagnosis (work in progress; sections filled incrementally).

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

TODO: strictest-secure option (A complete-the-posture vs B do-not-pin-for-client), invariant
enforcement, exact fns + tests.

## 7. Risks / collisions

TODO: exit-adapter A2, Gap A (10e7532a), M1 DNS backup (MacosDnsBackupRebootSurvivalPlan),
S1 re-assert (S1S4FixDesign), role-split investigation overlap.

## 8. Unknowns / needs a live probe

TODO: resolv.conf contents, all enabled networksetup services, whether loopback:53 answers,
scutil resolver section detail.
