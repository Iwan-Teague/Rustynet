# Adversarial Review — MacosClientDnsFailclosedDiagnosis_2026-09-02

**Reviewed document:** `documents/operations/active/MacosClientDnsFailclosedDiagnosis_2026-09-02.md` (merged at f01dc4fb, docs-only, no code changes)
**Review date:** 2026-09-02
**Method:** every code citation in the diagnosis was re-anchored against the current tree (`crates/rustynetd/src/`), the split-horizon question was investigated in the actual code (not the doc's claims), and the SecurityMinimumBar / Requirements text was re-read directly.

## Verdict: ACCEPT-WITH-AMENDMENTS

The diagnosis's core decision is correct and survives adversarial scrutiny:

- A plain client (`ExitMode::Off`) must **not** receive the M1 pin+floor bundle. On macOS the networksetup pins point `127.0.0.1:53` where **nothing listens** (the daemon binds `127.0.0.1:53535`, `daemon.rs:12209`) — the pins are hollow by construction, and the diagnosis's "never half-applied" invariant is the right posture for the full bundle.
- The R1 (apply-time live verification), R2 (re-render clobber), and R3 (startup residue ordering) fixes are grounded in real code defects — each verified below.
- R1's ordering is achievable with no chicken-and-egg problem: the resolver is bound in the daemon run loop (`daemon.rs:12209`) before any phase-10 apply runs.

**However, the make-or-break item (§4.2 of this review) finds a real gap:** the binary `FullyProtected | Untouched` posture misses a legitimate third state — **scoped split-horizon DNS** — and leaving a plain client fully untouched silently breaks Magic DNS for `*.rustynet` names on macOS and leaks those query names to the LAN resolver. This does not flip the verdict (the full-tunnel-or-untouched decision about the *pins and floor* is right), but it changes the required fix direction for the plain client, and the diagnosis document must be amended.

The amendments are numbered A1–A8 in §6. A1 is substantive (posture model + fix direction); A2–A5 are citation corrections; A6–A8 are confirmations with sharpened anchors.

## Per-anchor re-verification table

Legend: **VERIFIED** = current line(s) match the doc's claim; **NEAR** = correct symbol/claim, line drifted or omitted context; **STALE** = points at related but wrong location; **WRONG** = wrong file or wrong-OS context.

| # | Doc claim (as cited) | Actual location | Status |
|---|---|---|---|
| 1 | `apply_dns_protection` phase10.rs:4609–4740 | phase10.rs:4609–4742 (macOS impl; trait method :673, DryRun :948, Linux :3281–3313) | VERIFIED |
| 2 | sets `dns_protected = true` :4610 | phase10.rs:4610 | VERIFIED |
| 3 | `apply_pf_rules(false)` first :4611; pf failure → false + Err :4612–4613 | phase10.rs:4611–4613 | VERIFIED |
| 4 | S1 comment :4615–4636 (dns_protected stays TRUE on SC failure) | phase10.rs:4615–4636 | VERIFIED |
| 5 | M1 service enumeration :4637; backup-capture guard :4640–4649; prior-backup read :4654–4664; baseline resolve :4665–4678 | phase10.rs:4637–4678 | VERIFIED |
| 6 | backup written before first mutation :4684–4687 | phase10.rs:4679–4687 | VERIFIED (widened range) |
| 7 | pin loop :4688–4698 | phase10.rs:4688–4698 (`networksetup_setdns_loopback_args`, 127.0.0.1) | VERIFIED |
| 8 | resolv.conf write + clobber comment :4713–4720 / :4726–4728 | phase10.rs:4699–4720 (write), clobber comment :4706–4712 | NEAR (line drift) |
| 9 | `/etc/resolver/rustynet` scoped write :4733–4740; "unprivileged, cannot bind :53, scoped `*.rustynet` ONLY" :4726–4728 | phase10.rs:4721–4740; comment block :4721–4732 (the quoted sentences at :4726–4728, "Scoped to the rustynet domain only" :4731–4732) | VERIFIED |
| 10 | residue-guard refusal macos_dns_sc_protect.rs:425 | macos_dns_sc_protect.rs:425 ("residue from a prior apply whose teardown did not run") | VERIFIED |
| 11 | `render_macos_killswitch_pf_rules` :3442+; emission iff `!strict_fail_closed && spec.dns_protected` :3458/:3462–3479 | phase10.rs:3442; `if !strict_fail_closed` :3458; `if spec.dns_protected` :3462; pass out :53 :3463–3470; block DNS_BLOCK labels :3471–3478 | VERIFIED |
| 12 | `killswitch_spec()` copies dns_protected :3714–3726 / :3718 | phase10.rs:3714–3726, copy at :3718 | VERIFIED |
| 13 | `apply_pf_rules` :3796–3854; blind-exit live verification :3845; killswitch branch no verification :3852 | phase10.rs:3796–3854; blind-exit verify block :3830–3852 (`evaluate_macos_blind_exit_pf_rules` :3845, loud failure :3846–3851); killswitch branch ends `Ok` at :3853 | VERIFIED with clarification — :3852 is the closing brace of the blind-exit verify block; the doc's claim (killswitch branch has no live verification) is TRUE |
| 14 | fresh-instance `dns_protected = false` :9554 | :9554 is inside the **Windows** test `windows_command_system_rollback_dns_protection_is_no_op_when_not_applied` (phase10.rs:9545–9565) | **WRONG** (wrong-OS context). True macOS fresh-instance init: phase10.rs:3600 (MacosCommandSystem); DryRun :1148 |
| 15 | re-render callers :4488/:4496/:4541 | `apply_peer_endpoint_bypass_routes` :4460–4492 (re-render ~:4487–4491); `apply_firewall_killswitch` :4494–4497 (apply_pf_rules(false) :4496); `apply_nat_forwarding` pre-NAT :4541–4543 | VERIFIED |
| 16 | `serve_exit_node` calls `apply_dns_protection` :4551 | phase10.rs:4551 (inside apply_nat_forwarding, after activate_exit_nat) | VERIFIED |
| 17 | `rollback_dns_protection` :4790–4817 | phase10.rs:4790+ (false :4791; DnsFailclosedFile restore :4805/:4812) | VERIFIED |
| 18 | `assert_killswitch` :4831–4885 | phase10.rs:4831+ | VERIFIED |
| 19 | `assert_dns_protection` :4744–4788 | phase10.rs:4744+ (dns_protected gate :4745; per-service read :4774) | VERIFIED |
| 20 | `read_networksetup_dns_pin` :493–515 (file not stated) | **macos_dns_failclosed.rs:493** (doc comment :486–492: unpinned = inherits DHCP, can leak; None fails closed) | NEAR — line correct, **file omitted** in doc |
| 21 | macos_dns_failclosed.rs evaluate :159–205 | `evaluate_macos_dns_failclosed` :137; snapshot evaluation :159–205 (resolv_conf :163, nameservers empty :170, `loopback_resolver_advertised` :177–181, pf_block_rules :185–191, networksetup_readable :193–197, unpinned loop :199–203) | VERIFIED |
| 22 | conditions :242–272 | adjacent helpers (`loopback_resolver_advertised_from_scutil` :281) | NEAR |
| 23 | conditions :327–343 | adjacent snapshot build :362–386 | NEAR |
| 24 | :81–82 owned-anchor prefixes | macos_dns_failclosed.rs:81–82 (`MACOS_RUSTYNET_OWNED_ANCHOR_PREFIXES`) | VERIFIED |
| 25 | build_report :530–541 | `build_macos_dns_failclosed_report` :530–541 (drift_reasons + overall_ok :533–534) | VERIFIED |
| 26 | daemon.rs:12209 resolver bind | daemon.rs:12209 (UnixListener, then UDP bind — in the run loop, **before** phase-10 apply) | VERIFIED |
| 27 | daemon.rs:444 `DEFAULT_DNS_RESOLVER_BIND_ADDR = "127.0.0.1:53535"` | daemon.rs:444 | VERIFIED |
| 28 | daemon.rs:11843 probe bind (10 retries) | daemon.rs:11843 | VERIFIED |
| 29 | daemon.rs:13268–13281 Windows :53 normalize | `normalize_windows_dns_resolver_bind_addr` :13268–13282 | VERIFIED |
| 30 | linux_dns_protect.rs:20–24 nft redirect :53→:53535; :182/:191 "Scoped to `rustynet` ONLY" | linux_dns_protect.rs:21–24, :188, :191 | VERIFIED |
| 31 | macos_exit_dns_failclosed.rs:700–701 / :783–784 DNS_BLOCK labels | labels **defined** at macos_exit_dns_failclosed.rs:35–36 (`DNS_BLOCK_LAN_UDP_RULE` / `DNS_BLOCK_LAN_TCP_RULE`); :700–701 are **test-body usages** | STALE-but-adjacent |
| 32 | Mesh-name scoping of the loopback resolver (split-horizon premise) | phase10.rs:4721–4732 + linux_dns_protect.rs:188/191: the scoped resolver covers the `rustynet` domain only | VERIFIED — this is the load-bearing fact for §4.2 |

## §4.2 Split-horizon determination (make-or-break item)

**Finding: the diagnosis's binary posture (`FullyProtected | Untouched`) is missing a real third state. The plain-client "fully untouched" recommendation, taken literally, removes the one macOS DNS artifact that actually works — the domain-scoped `/etc/resolver/rustynet` file — and thereby (a) breaks Magic DNS for mesh names and (b) leaks mesh query names to the LAN resolver.**

The mechanism, from the code:

- M1 (`apply_dns_protection`) bundles five artifacts: the pf DNS-block floor, all-service networksetup loopback pins, the resolv.conf overwrite, the **scoped** `/etc/resolver/rustynet → 127.0.0.1:53535` file (phase10.rs:4721–4740), and the backup document.
- Of these, on macOS only the scoped resolver **functions**: the daemon genuinely listens on `127.0.0.1:53535` (`daemon.rs:12209`), and `/etc/resolver/<domain>` is macOS's native split-horizon mechanism — the comment in phase10.rs:4731–4732 states the intent explicitly: *"Scoped to the rustynet domain only — no other domain's resolution changes."*
- The pins are hollow (nothing listens on :53), and the pf floor + resolv.conf overwrite are full-tunnel posture.

So macOS already has split-horizon by design: `*.rustynet` → loopback scoped resolver; everything else → normal DHCP/LAN resolver. The diagnosis correctly decides that a plain client must not get the pins/floor. But "fully untouched" also deletes the scoped resolver, and then:

1. `*.rustynet` mesh names stop resolving on a plain client — breaking the Magic DNS client capability in `Requirements.md` §3.5 (:92–97: internal zone `*.rustynet`, hostname records, search-domain support for clients).
2. Worse, a query for a mesh hostname (e.g. `exit-1.rustynet`) goes to the **LAN/DHCP resolver**, which forwards it upstream. The query *name* — which reveals mesh topology — leaks outside Rustynet policy. That is a mesh-name leak even though it is not a general-DNS leak.

**Compliance framing (important, and the diagnosis should say it plainly):** `SecurityMinimumBar.md` control 8 (:240–242) is explicitly conditional — *"DNS fail-close behavior in protected DNS modes"* — as are `Requirements.md`:90 and :186. A plain client in `ExitMode::Off` is not a protected DNS mode, so "untouched" is **letter-compliant**; the diagnosis's compliance argument stands. The amendment rests on Requirements §3.5 (Magic DNS must work for clients) plus the security-first posture on mesh-name privacy — i.e. A1 is a **functionality + privacy fix**, not a bar violation. The diagnosis's own §5 correctly cites the conditionality; it just doesn't follow the scoped-resolver consequence through.

**Corrected fix direction for the plain client:** a third posture, `ScopedResolverOnly` — write `/etc/resolver/rustynet` (and only that file; no pins, no pf floor, no resolv.conf overwrite), gated on the daemon actually listening on 53535. This is exactly the split-horizon client the platform supports natively, it cannot hollow-fail the way the pins do (the listener is verified before the write), and it is trivially removable at teardown.

**Verifier consequence:** the macos-dns-failclosed verifier's seven-condition contract (loopback primary advertised, all services pinned, pf floor present, …) is the **full-tunnel** contract and must NOT be applied to a plain client (this part of R4 is right). But with A1, the plain-client verifier should assert exactly one condition — `scoped_resolver_present` (plus the listener probe) — rather than dropping to zero conditions. That keeps the mesh-name guarantee testable.

## §6 Numbered findings and exact amendments

- **A1 (substantive — split horizon, §4.2 above).** Amend the diagnosis's §5 decision and the offline-core `DnsPosture` model: add a third outcome `ScopedResolverOnly` (inputs gain `scoped_resolver_present` and `resolver_listening`), and change the plain-client fix from "fully untouched" to "scoped resolver only (`/etc/resolver/rustynet`, listener-verified; no pins, no floor, no resolv.conf)". The plain-client verifier condition is `scoped_resolver_present`, not zero conditions. Exact replacement text for the decision sentence: *"A plain client in ExitMode::Off receives only the domain-scoped resolver `/etc/resolver/rustynet` → 127.0.0.1:53535 (written only after the daemon's listener is verified live); it never receives the networksetup pins, the pf DNS-block floor, or the resolv.conf overwrite. This preserves Magic DNS for *.rustynet and keeps mesh-name resolution inside Rustynet policy, while general DNS remains the machine's normal resolver."*
- **A2 (citation — wrong-OS anchor).** The doc's ":9554 fresh-instance `dns_protected=false`" points at a **Windows** test (`windows_command_system_rollback_dns_protection_is_no_op_when_not_applied`, phase10.rs:9545–9565). The macOS fresh-instance init is phase10.rs:3600 (DryRun :1148). Replace the citation. The R2 clobber premise itself remains **real and verified**: see A8.
- **A3 (citation — omitted file).** `read_networksetup_dns_pin` lives in **macos_dns_failclosed.rs:493** (doc comment :486–492), not in `macos_dns_sc_protect.rs` and stated with no file in the doc. Add the file.
- **A4 (citation — stale line).** The `DNS_BLOCK_LAN_UDP_RULE` / `DNS_BLOCK_LAN_TCP_RULE` labels are **defined** at macos_exit_dns_failclosed.rs:35–36; the doc's :700–701 (and :783–784) are test-body usages. Re-anchor to :35–36.
- **A5 (citation — clarify).** ":3852 killswitch branch no verification": :3852 is the closing brace of the blind-exit **live-verification** block (phase10.rs:3830–3852, `evaluate_macos_blind_exit_pf_rules` :3845); the killswitch branch then completes with an unverified `Ok` at :3853. The doc's claim is TRUE; clarify the anchor to ":3830–3853 (killswitch branch: no live verification)".
- **A6 (confirmation — R1 ordering feasible).** No chicken-and-egg: the resolver binds in the daemon run loop (daemon.rs:12209) before any phase-10 apply; the exit-path `apply_dns_protection` is invoked from `apply_nat_forwarding` (phase10.rs:4551) after the run loop is live. The new apply sequence can verify bind **and answer** (UDP probe to 53535) before writing the scoped resolver and before pinning. Recommend the scoped-resolver write be gated on the same live-probe result.
- **A7 (confirmation — R4 is not a weakening, with a condition).** Role-scoping the lab verifier is correct alignment, not weakening, **provided** (i) a half-state remains drift/failure under every role, and (ii) with A1, the plain-client verifier asserts `scoped_resolver_present` instead of silently dropping to zero conditions. The exit/full-tunnel seven-condition contract is unchanged.
- **A8 (confirmation — R2/R3 real and correctly ordered).** Verified: fresh macOS instances start `dns_protected=false` (phase10.rs:3600; DryRun :1148) and the re-render callers — `apply_peer_endpoint_bypass_routes` (~:4487–4491), `apply_firewall_killswitch` (:4496), `apply_nat_forwarding` pre-NAT (:4541–4543) — call `apply_pf_rules(false)` while `dns_protected` may still be true, producing a floor-less pf anchor while pins persist. R2's detection-via-`read_networksetup_dns_pin` fix addresses this. R3's ordering is right and load-bearing: startup residue cleanup (`macos_dns_sc_protect.rs` `decide_startup_recovery` :538) must run **before** M1's backup-capture guard (phase10.rs:4640–4649), else the residue refusal at macos_dns_sc_protect.rs:425 fails every subsequent apply.

## §7 Considered, no defect

- **S1 posture-retention on SC failure (phase10.rs:4615–4636) + re-assert machinery (daemon.rs:10807–10835, periodic :10827):** keeping `dns_protected=true` so the next reconcile cannot render a floor-less anchor is correct; the 30s re-assert loop is the fail-closed complement. No change.
- **Backup-before-mutation (phase10.rs:4679–4687) with unreadable-backup refusal (:4654–4664):** correct ordering and fail-closed on unreadable state.
- **Scoped-resolver-only write semantics (:4721–4732):** the file-level scoping comment is accurate; the problem is bundling, not the artifact.
- **Linux parity:** linux_dns_protect.rs redirects :53→:53535 via nft (:21–24), so pins **answer** on Linux — the hollow-pin defect is genuinely macOS-only, as the diagnosis states.
- **Shared DNS_BLOCK labels with the exit verifier:** macos_exit_dns_failclosed.rs:35–36 labels reused by the killswitch render (:3471–3478) is intentional convergence; the exit role's own failclosed verifier remains the authority for exit-mode checks.
- **M1 bundling itself:** for the **exit** role the five-artifact bundle is appropriate; the defect is applying the bundle to a plain client, which the diagnosis already forbids.

## §8 Offline-testable core

The diagnosis's proposed pure function and tests are implementable as specified, with the A1 extension: `macos_dns_posture_decision(resolver_answering, pf_floor_live, pins_present, scoped_resolver_present)` returning `FullyProtected | ScopedResolverOnly | Untouched` (no `Half` — any partial full-tunnel state remains a decision error), plus the render-refusal test, the DryRun op-count tests, and role-scoped verifier tests. Add per A1: scoped-resolver-present / absent decision tests and a plain-client verifier test asserting `scoped_resolver_present`.
