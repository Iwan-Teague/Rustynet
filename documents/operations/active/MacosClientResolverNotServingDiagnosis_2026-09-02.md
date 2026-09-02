# macOS Client Resolver Not Serving — Diagnosis (2026-09-02)

**Status:** DIAGNOSIS, docs-only. No code changed.
**Context:** The macOS DNS three-state posture fix (`345fe219`, merged) is correct and
fail-closed; its live proof (`cc25ceac` records the harvest) exposed this deeper defect.
**Symptom:** on `macos-utm-1` (plain mesh client, `ExitMode::Off`), the daemon log shows

```
dns apply failed: the loopback DNS resolver on 127.0.0.1:53535 did not answer
```

repeated over ~30 s; each apply rolls back fail-closed; the node ends PERMANENTLY
restricted, so BOTH `validate_baseline_runtime` checks fail (`macos-utm-1/DnsFailclosed`
and `macos-utm-1/MeshStatus` — a restricted node cannot mesh).

All file:line citations below were read from the working tree at diagnosis time
(branch `ai-edit/edit-1788388747110-25220-0`, HEAD `cc25ceac`).

## 1. Q1 — Why does the client's loopback resolver at 127.0.0.1:53535 not answer?

**Answer: (c) — an ordering defect, and stronger than a race: it is deterministic.
The probe runs BEFORE the DNS socket is even bound. It can never succeed during
bootstrap.** (a) and (b) are NOT the cause, per the evidence below.

### 1.1 The serving path (what would answer)

- The bind: `crates/rustynetd/src/daemon.rs:12209`
  (`UdpSocket::bind(config.dns_resolver_bind_addr)`, nonblocking at :12212), default
  `127.0.0.1:53535` (`daemon.rs:444`, `DEFAULT_DNS_RESOLVER_BIND_ADDR`), which equals the
  probe's port (`linux_dns_protect.rs:188`, `MACOS_SCOPED_RESOLVER_LOOPBACK_PORT`).
- The serve loop: `daemon.rs:12353-12369` — inside `run_daemon`'s MAIN `loop`, an
  inner `dns_socket.recv_from(...)` drain that calls `build_dns_response` and
  `send_to`s the reply. **It is not role-gated in any way** — a plain client runs the
  same loop as an exit.
- The answering logic: `build_dns_response` (`daemon.rs:12459-12520`) **always returns a
  reply for any parseable query**: REFUSED for out-of-zone names (:12478-12484), REFUSED
  for non-IN class (:12485-12491), SERVFAIL when the signed zone is absent/erroring
  (:12492-12498), otherwise the resolved record / NOERROR. The probe
  (`phase10.rs:4532-4573`) only requires *a* reply echoing its transaction id
  (:4567) — a REFUSED or SERVFAIL reply passes it. **So neither a loaded signed DNS zone
  nor any role capability is needed to answer the probe.** (b) is moot for the probe.
- Zone loading (`refresh_dns_zone_state`) happens at `daemon.rs:8931` (bootstrap,
  after a SUCCESSFUL apply) and `daemon.rs:10664` (reconcile, after apply) — i.e. after
  the applies; the lab's `distribute_dns_zone` delivers the bundle, and the client's
  daemon loads it at those points. Irrelevant to why the probe got silence, but relevant
  to §6 (whether the client's Magic DNS actually resolves names once served).

### 1.2 The ordering (why nothing answers)

`run_daemon` (`daemon.rs:11712`) executes, in order:

1. `:11789` macOS startup DNS recovery (M1 residue guard);
2. `:11804` `DaemonRuntime::new`;
3. **`:11812` `runtime.bootstrap()`** — which, via `bootstrap()` (`daemon.rs:8623`),
   calls `apply_dataplane_generation` (`daemon.rs:8878`) with `protected_dns: true`
   (:8889). Inside that apply, `phase10.rs:7270-7278` decides the posture
   (`macos_dns_posture`, `phase10.rs:783-789`: `ExitMode::Off` + not serving exit ⇒
   `ScopedResolverOnly`) and calls `apply_scoped_resolver_only`
   (`phase10.rs:4604`), whose FIRST step is the probe
   (`verify_loopback_resolver_live`, `phase10.rs:4605`, defined :4532);
4. **`:12209` the DNS socket is bound** — only after bootstrap returns;
5. `:12353` the serve loop starts draining — only once the main `loop` begins.

So at the moment the probe sends its RFC 1035 query, **no socket exists on
127.0.0.1:53535 in this process at all**. UDP `connect` to a listener-less loopback
port succeeds, the `send` succeeds, and the `recv` then fails (ICMP port-unreachable /
timeout), producing exactly the observed `did not answer` error string
(`phase10.rs:4562-4566`). This is not a scheduling race: bootstrap completes entirely
before the bind. **No intra-apply bounded-retry can fix it** — the bind happens only
after bootstrap returns, so retries inside the apply see the same dead port.

### 1.3 Collateral: the exit/full-tunnel path shares the defect

`apply_dns_protection` (the `FullyProtected` sequence, `phase10.rs:4961`) probes at
`phase10.rs:4969` with the same first-step semantics. Every macOS apply during
bootstrap carries `protected_dns: true` (`daemon.rs:8889` bootstrap; `:10579`
reconcile), so a macOS exit / full-tunnel node hitting `FullyProtected` at BOOTSTRAP
time would fail the same way. No macOS exit/full-tunnel live cell has run since
`345fe219` merged, so this exposure is predicted from code, not yet observed live
(see §6). Reconcile-time applies are unaffected: by then the main loop (and the serve
loop) is live.

Windows is unaffected today: its branch binds the resolver at `daemon.rs:11838-11869`
(also after bootstrap, with retry), but the Windows DNS posture path
(`windows_dns_failclosed.rs`) does not use this loopback probe.

## 2. Q2 — Should a client's DNS-apply failure restrict the whole node?

**Answer: No — for the client `ScopedResolverOnly` posture, a DNS sub-step failure
should fail ONLY the DNS posture closed; mesh connectivity must not be taken down.
For `FullyProtected` (exit / full-tunnel), full-apply failure and restriction remain
correct.**

### 2.1 How the DNS sub-step failure currently becomes whole-node restriction

- The probe error is `SystemError::DnsApplyFailed` (`phase10.rs:4562-4566`, rendered
  `dns apply failed: …` at `phase10.rs:462`) and propagates via `?` from
  `apply_dns_protection_for_posture` (`phase10.rs:7276`) out of
  `apply_dataplane_generation` as the WHOLE apply's `Err`.
- Bootstrap: `daemon.rs:8909-8912` — `restrict_recoverable("dataplane bootstrap apply
  failed: …")` + `force_fail_closed_or_restrict("bootstrap_apply_failed")`.
- The loop then re-applies every pass: the re-apply predicate
  (`daemon.rs:10440-10448`, `:10463-10465`) fires while
  `RestrictionMode::Recoverable`, each pass re-runs the 2 s probe + rollback, and
  `reconcile_failures` increments per failure (`daemon.rs:10695-10701`).
- At `DEFAULT_MAX_RECONCILE_FAILURES = 5` (`daemon.rs:552`, interval
  `DEFAULT_RECONCILE_INTERVAL_MS = 1000` at `daemon.rs:498`),
  `promote_to_permanent_if_over_limit` (`daemon.rs:10980-10987`) flips
  `RestrictionMode::Permanent`. Five failed passes at ~5-6 s each ≈ the observed ~30 s
  repetition, after which `DnsFailclosed` AND `MeshStatus` both fail — the killswitch
  fail-closed state blocks the mesh that `MeshStatus` checks.

### 2.2 Requirements / SecurityMinimumBar scoping

- `documents/Requirements.md:90`: "**DNS fail-close behavior must prevent DNS leakage
  outside Rustynet policy when VPN mode requires protected DNS.**" — scoped to
  protected-DNS VPN modes. A plain client (`ExitMode::Off`, `ScopedResolverOnly`) is by
  construction NOT a protected-DNS mode: its machine DNS is untouched; only
  `*.rustynet` is scoped (`phase10.rs:755-759`).
- `documents/Requirements.md:186`: "VPN operating modes requiring protected routing
  must fail closed for traffic and DNS on tunnel failure." — again the
  protected-routing modes; the client's mesh path is the ordinary tunnel fail-close
  domain (§3.4), a separate control from Magic DNS (§3.5).
- `documents/SecurityMinimumBar.md` §8: "**DNS fail-close behavior in protected DNS
  modes.**" — same scoping.
- Strictest-secure reading: on probe failure the apply rolls back to
  `DnsPosture::Untouched` (`rollback_after_failed_apply`, `phase10.rs:4578-4583` — the
  probe runs BEFORE any mutation, so the rollback is trivially clean; nothing was ever
  written). **The node is left in a zero-leak DNS state** — no scoped file pointing at
  a dead resolver, no pins, no floor residue. There is no trust-state violation, no
  leak, no residue. Restricting the WHOLE node (fail-closed killswitch ⇒ no mesh) is
  over-broad for that posture: it converts a self-inflicted ordering defect into a
  permanent connectivity loss with no security gain. For `FullyProtected`, by contrast,
  a DNS apply failure IS leak-relevant (general pins, pf floor, resolv.conf rewrite),
  the mutation surface is the machine's entire resolution, and the current
  full-apply-failure restriction is the correct strict behavior.

## 3. Recommended fix direction

**Primary (ordering — required either way): the DNS-posture sub-apply must run only
once the daemon's DNS serve path is live.** Concretely, one of:

1. **Defer the DNS sub-step out of bootstrap into the first reconcile pass** (after the
   main loop binds :12209 and the drain at :12353 is running). `apply_dataplane_generation`
   would skip the `apply_dns_protection_for_posture` + `assert_dns_protection` stage
   (`phase10.rs:7270-7278`) for the bootstrap call, and the daemon schedules the posture
   apply as a first-pass latch (reusing the `dns_posture_reassert_pending` pattern,
   `daemon.rs:4756`/`:10607`, so the S1 ladder covers it). Both probe call sites
   (`phase10.rs:4605` scoped, `:4969` full) then execute only against a live listener.
   This is the smallest change consistent with §3's one-hardened-path rule: the probe,
   the fail-closed rollback, and the three-state posture decision are all preserved
   verbatim; only their invocation timing moves.
2. Bind the DNS socket BEFORE `runtime.bootstrap()` (`daemon.rs:11812`) AND drain it
   during bootstrap. Larger, more invasive (bootstrap is synchronous; draining needs a
   re-entrant pump or a thread), and buys nothing over (1) security-wise.

Bounded probe retry alone is INSUFFICIENT in either option's absence (§1.2): within
bootstrap the listener does not exist yet, so retries cannot observe it.

**Secondary (Q2 decoupling): split DNS-apply failure from whole-node restriction for
`ScopedResolverOnly` only.** A failed client posture apply restricts the DNS posture
(posture stays rolled-back/untouched, Magic DNS unavailable, surfaced via
`last_reconcile_error` + the S1 re-assert ladder) but the mesh dataplane apply
succeeds. `FullyProtected` failures keep today's full-apply fail-closed semantics.

**Rejected: option (ii) — client posture `Untouched` with no scoped resolver.** That
removes the ONLY route from the OS resolver to mesh names for a plain client
(`phase10.rs:5091-5099`: `/etc/resolver/<domain>` is the sole mechanism; there is no
peer DNS forwarding over the tunnel today), so §3.5 Magic DNS silently stops working
for every macOS client — a capability regression, not a hardening. It would also leak
`*.rustynet` query names to the LAN resolver (the exact leak the scoped posture
exists to prevent, `phase10.rs:755-759`). `Untouched` remains correctly reserved for
the `protected_dns=false` opt-out (`phase10.rs:760-763`).

## 4. Risks / collisions

- **The just-merged three-state fix (`345fe219`):** preserved, not weakened — the
  probe, its pre-mutation position within the posture apply, the all-or-nothing
  rollback, and the posture decision all stay; only WHEN the apply runs changes. The
  existing apply-time-probe tests (e.g. `phase10.rs:17439-17449`, which expects the
  `127.0.0.1:53535` error when no daemon is bound) must move to the new invocation
  surface.
- **Gap A (`10e7532a`, post-restart signed-state refresh;**
  `MacosClientDnsFailclosedDiagnosis_2026-09-02.md` §7):** the deferred apply runs on
  the first reconcile pass, the same pass the Gap A refresh exercises. The signed-state
  refresh must complete BEFORE the deferred posture decision, or the fresh instance
  judges a half-delivered state (same ordering rule that diagnosis already records).
- **Exit-serving adapter (`LiveLabMacosExitServingAdapterDesign_2026-09-02.md`):** the
  adapter drives macOS into exit role; the bootstrap-time `FullyProtected` probe
  (`phase10.rs:4969`) has the SAME dead-listener exposure (§1.3) and would fail the
  adapter's cells the same way. The fix MUST cover both postures' bootstrap timing,
  and the exit DNS-block rule emission shared with `macos_exit_dns_failclosed.rs`
  must stay byte-identical.
- **S1 re-assert (`MacosDnsFailclosedS1S4FixDesign_2026-08-31.md`):** the deferred
  first-pass apply should reuse the single re-apply latch so a transient failure heals
  through the existing ladder rather than pinning in a loop; under the Q2 decoupling a
  failed client posture restricts DNS only and the re-assert gates on posture health.
- **M1 backup / residue guard (`MacosDnsBackupRebootSurvivalPlan_2026-09-02.md`):** a
  deferred `FullyProtected` apply still must run startup recovery + the residue guard
  first (`daemon.rs:11789` ordering is already before bootstrap and unchanged).
- **Linux / Windows:** unaffected. Linux answers `:53535` behind the nft `:53`→`:53535`
  redirect (`linux_dns_protect.rs:20-24`) and its DNS stage has no such probe-before-bind
  path in this form; Windows normalizes the bind to `:53` (`daemon.rs:13268-13281`) and
  uses no loopback probe.
- **Baseline stages:** with the fix, `macos-utm-1/DnsFailclosed` and
  `macos-utm-1/MeshStatus` should both return to pass; the acceptance run must verify
  the stage's own report artifacts, not the matrix row alone (§10.9 rule).

## 5. Unknowns / needs a live probe

1. **Does the client's served resolver actually resolve mesh names once the loop is
   live?** On a healthy running client: `dig @127.0.0.1 -p 53535 a-name.rustynet` —
   distinguishes an A answer (signed zone loaded) from SERVFAIL (bundle delivered by
   `distribute_dns_zone` but not loaded, or load failing). The probe passes either
   way; Magic DNS correctness does not.
2. `/etc/resolver/rustynet` content + `scutil --dns` output after a successful scoped
   apply on the client — confirms mDNSResponder routes `*.rustynet` to :53535.
3. Whether a macOS exit / full-tunnel node on this commit actually fails bootstrap via
   the `:4969` probe (predicted §1.3, unobserved). The exit-serving adapter cells will
   surface it; or probe directly with a short focused run before the fix lands.
4. Exact repetition cadence on the guest (~30 s observed vs the ~15-30 s predicted from
   5 × (2 s probe + rollback + helper round-trips)) — confirms which ladder promoted to
   permanent (bootstrap failures + reconcile passes vs crash-loop restarts).
