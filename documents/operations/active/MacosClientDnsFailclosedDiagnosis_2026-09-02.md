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

TODO(filled from grounded research): step-by-step of apply_dns_protection (~:4609);
apply_pf_rules(false) call; what governs DNS-block rule emission; verdict intentional vs defect.

## 4. Loopback resolver & scutil primary

TODO(filled from grounded research): resolver startup for plain client; what sets scutil
PRIMARY; why never loopback while services pinned.

## 5. Spec decision — does a plain mesh client REQUIRE protected DNS?

TODO(filled from grounded research): Requirements.md:90 / :186 reading; role/mode→DNS-protection
mapping in daemon; precedence decision per §2 doc order.

## 6. Chosen fix + offline-testable core

TODO: strictest-secure option (A complete-the-posture vs B do-not-pin-for-client), invariant
enforcement, exact fns + tests.

## 7. Risks / collisions

TODO: exit-adapter A2, Gap A (10e7532a), M1 DNS backup (MacosDnsBackupRebootSurvivalPlan),
S1 re-assert (S1S4FixDesign), role-split investigation overlap.

## 8. Unknowns / needs a live probe

TODO: resolv.conf contents, all enabled networksetup services, whether loopback:53 answers,
scutil resolver section detail.
