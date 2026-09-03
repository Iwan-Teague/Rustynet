# Adversarial Refute Review — macOS DNS Resolver Ordering Fix (M1–M4)

**Date:** 2026-09-03
**Scope under review:** commits `83433dd1` (M1, "hoist DNS resolver bind above bootstrap; answer bootstrap probe via shared responder"), `f75869e2` (M2, "defer ScopedResolverOnly DNS posture out of bootstrap to first reconcile"), `cc4449c5` (M3, "ScopedResolverOnly DNS-apply failure no longer restricts the node"), `b93376ca` (M4, docs) — reviewed as the full diff `2f7f9919..HEAD` (merge-base with `origin/main`): `crates/rustynetd/src/daemon.rs` (+744/−79), `crates/rustynetd/src/phase10.rs` (+330), `documents/CODE_MAP.md`, `documents/operations/active/ClientResolverNotServingDiagnosis_2026-09-02.md`.
**Method:** adversarial — every question was framed as an attempt to *refute the fix's safety*, i.e. to find a leak window, a fail-open path, a race, or a weakened check. All citations below are from the real code at HEAD (`b93376ca`) in this worktree; `daemon.rs` = `crates/rustynetd/src/daemon.rs`, `phase10.rs` = `crates/rustynetd/src/phase10.rs`.

> **SUMMARY VERDICT: NO CONFIRMED SECURITY PROBLEM FOUND.** All five adversarial questions came back REFUTED — the fix is safe on each point. Two non-security observations are recorded under finding 5 for the ledger; neither is a regression introduced by M1–M4.

---

## Finding 1 — LEAK WINDOW: FullyProtected is applied during bootstrap, never deferred

**VERDICT: REFUTED** (no leak window; the deferral provably cannot reach a FullyProtected node).

The deferral is a *conjunctive* gate, not a posture-independent flag. At the single apply site, `apply_dataplane_generation` (`phase10.rs:7376-7399`):

```rust
if options.protected_dns {                                    // 7376
    let posture = macos_dns_posture(...);                     // 7381
    if options.defer_scoped_dns_posture
        && posture == DnsPosture::ScopedResolverOnly {        // 7382 — BOTH must hold
        // NO ops at all: no probe, no scoped-file write, no assert;
        // generation's DNS posture remains exactly Untouched (7390-7393)
    } else {
        self.system.apply_dns_protection_for_posture(posture)?;   // 7394
        applied_stages.push(StageMarker::DnsApplied);             // 7396
        self.system.assert_dns_protection()?;                     // 7397
    }
}
```

A FullyProtected node (exit selected, or full-tunnel client — `macos_dns_posture` maps `FullTunnel || serve_exit_node → FullyProtected`, `phase10.rs:800-806`; mapping covered by tests at `phase10.rs:812-834`) fails the `posture == ScopedResolverOnly` half of the conjunct and takes the `else` branch: full protection (scoped resolver + per-service networksetup loopback pins + pf DNS-block floor via `apply_dns_protection()`; `apply_dns_protection_for_posture`, `phase10.rs:5206-5217`) is applied and asserted **during bootstrap, exactly as before**. The `ApplyOptions` doc comment states this invariant explicitly and gives the reason: deferring the full posture "would leave a tunnel-up node resolving general DNS with no pf floor and no pins — real leak window" (phase10 diff, `defer_scoped_dns_posture` field docs).

Both daemon call sites pass `protected_dns: true` (`daemon.rs:8899` bootstrap, `daemon.rs:10612` reconcile), so the enclosing gate never silently disables DNS handling. The bootstrap `defer_scoped_dns` computation itself is posture-guarded: `defer_scoped_dns = cfg!(target_os = "macos") && macos_dns_posture(bootstrap_exit_mode, serve_exit_node) == DnsPosture::ScopedResolverOnly` (`daemon.rs:8865-8885` hunk) — a second, independent posture check before the flag even reaches `ApplyOptions`. Regression tests pin both sides: `bootstrap_defer_flag_never_defers_fully_protected_posture` (defer flag set + FullTunnel/serve-exit + default route → ops DO contain `apply_dns_protection` + `assert_dns_protection`) and `bootstrap_deferred_scoped_posture_emits_no_dns_ops` (defer + plain client → no DNS ops).

## Finding 2 — FAIL-CLOSED PRESERVED: the deferred window is availability-only, zero-leak

**VERDICT: REFUTED** (the ScopedResolverOnly posture's only mutation is deferred with the posture; the deferred state is `Untouched`, which is the zero-leak state; the fail-closed scoped file still appears at first reconcile, driven by a latch that cannot be forgotten).

What is actually deferred: for a plain client, the ScopedResolverOnly posture consists of **only** the single `/etc/resolver/rustynet` scoped file — no general pins, no pf floor, no resolver rewrite (`DnsPosture` invariant docs, `phase10.rs:766-781`: "ScopedResolverOnly … machine DNS untouched"). The defer arm emits no ops, so during the bootstrap→first-reconcile window general DNS is byte-for-byte untouched — nothing was pinned, nothing was removed, no pf rules changed. There is no half-applied state: `Untouched` is a first-class posture and the enum invariant forbids anything between postures ("A half-applied general pin without a live loopback primary and a pf floor is never a valid posture", `phase10.rs:766-781`).

The window analysis:

- **Mesh-name resolution during the window** (bootstrap-complete → first reconcile): without the scoped file, `*.rustynet` queries fall through to the LAN resolver and return NXDOMAIN. That is an *availability* gap of at most one reconcile tick, not a leak — no mesh data moves, and the query leak (mesh names visible to the LAN resolver) is identical to the pre-fix state where a plain-client bootstrap *failed the probe outright* and left the node restricted (and in the worst pre-fix case climbing to Permanent restriction — strictly worse than one tick of unresolved names).
- **The heal is latched, not best-effort:** bootstrap sets `self.dns_posture_reassert_pending = true` on the `(Ok, Ok)` path when it deferred (`daemon.rs:8909-8916`, latch set at 8915). That latch is part of the reconcile-needed predicate (`daemon.rs:10461`) and is cleared only by a successful apply (`daemon.rs:10634`). Reconcile-time applies never defer (`defer_scoped_dns_posture: false` with the comment "reconcile-time applies NEVER defer — the serve loop is live by then", `daemon.rs:10619`). So the scoped fail-closed file is written on the first reconcile pass, deterministically, through the normal hardened apply path (S1 semantics documented at `phase10.rs:5084`, `daemon.rs:523`, `daemon.rs:10869-10897`). Test `bootstrap_defers_scoped_dns_posture_to_first_reconcile` proves the full sequence: bootstrap leaves no DNS ops and no restriction, latch set; reconcile emits `apply_dns_protection` and clears the latch.
- **Stale scoped file across restart** (daemon previously ran, wrote the file, restarted as a plain client with defer): the file keeps pointing `*.rustynet` at `127.0.0.1:53535`, which M1's hoisted socket now owns *before* bootstrap — so the stale file is served by the real responder: in-zone queries get SERVFAIL (fresh runtime has no zone loaded yet; `bootstrap_probe_servicer_responder_matches_live_responder`), out-of-zone get REFUSED. Fail-closed preserved; and the node can never be in the "file says loopback, nothing listening" state that made the original probe fail, because the socket is bound before any DNS apply can run.
- **No "serving traffic with mesh DNS neither protected nor fail-closed" hazard:** in the window the node serves mesh *data* over the tunnel (applied earlier in the same generation), and mesh *names* simply do not resolve locally — they cannot resolve to a wrong destination because nothing rewrites them; the LAN resolver returns NXDOMAIN for names that exist nowhere public. No path exists where a mesh name resolves to a non-mesh address.

## Finding 3 — M3 ERROR-PATH: softening is exactly scoped to ScopedResolverOnly + DnsApplyFailed, availability-only

**VERDICT: REFUTED** (FullyProtected failures keep the full restriction ladder; the softened branch cannot produce a half-applied leak and still re-arms the heal).

The new branch is doubly keyed (`daemon.rs:10740-10747`):

```rust
let scoped_dns_degraded = applied_dns_posture == Some(DnsPosture::ScopedResolverOnly)
    && matches!(err, Phase10Error::System(SystemError::DnsApplyFailed(_)));
```

`applied_dns_posture` is computed **before** the apply from the same `reconcile_exit_mode`/`serve_exit_node` the apply itself uses (`daemon.rs:10596-10600`), and is `None` on non-macOS — so a FullyProtected DNS failure, a rollback failure, an assert failure of any other stage, or any Linux/Windows failure falls through to the **original ladder byte-for-byte**: increment `reconcile_failures`, `restrict_recoverable`, `force_fail_closed_or_restrict("reconcile_apply_failed")`, `promote_to_permanent_if_over_limit` (`daemon.rs:10756-10763`). The `(Err, Err)` cleanup-failure case keeps the full ladder too (`daemon.rs:10765-10774`). FullyProtected regression coverage: `fully_protected_dns_apply_failure_still_restricts` — same `DnsApplyFailed` on an exit-selected runtime → `reconcile_failures == 1`, `RestrictionMode::Recoverable`, degraded flag *not* set; iterating to 5 → Permanent.

Why the softened branch is availability-only and never fail-open — the failure itself leaves the node in a safe state:

1. **The probe precedes every mutation.** `apply_dns_protection_for_posture` for ScopedResolverOnly probes the loopback resolver before touching anything; a probe failure means no scoped file was written, no pins changed, no pf rules changed — the posture is `Untouched`, the zero-leak state (M3 comment citing review §3.3 F4, `daemon.rs:10726-10739`).
2. **Mid-apply failure rolls back to Untouched.** A failure after mutation (`assert_dns_protection` drift, scoped-file write error) unwinds through the controller's rollback-to-Untouched path; a rollback failure surfaces as `RollbackFailed`, which does **not** match the `DnsApplyFailed` pattern and therefore takes the full ladder (`phase10.rs:5206-5217` sub-apply; `rollback_dns_protection` `phase10.rs:5277-5300+`, which also preserves the M1 teardown ordering — SC restore before pf anchor drop, failed SC restore keeps the anchor up and fails loud).
3. **The daemon-side softening is compensated by re-arming:** the degraded branch sets `dns_posture_reassert_pending = true` and `dns_scoped_apply_degraded = true`, records `last_reconcile_error`, and deliberately does *not* touch `reconcile_failures` or restriction state (`daemon.rs:10748-10755`). The next pass retries the whole apply through the unchanged hardened path; success clears the degraded flag and the latch (`daemon.rs:10712-10714`). `scoped_dns_apply_failure_does_not_restrict` and `scoped_dns_apply_failure_never_reaches_permanent` pin this end-to-end (8 passes, failures stay 0, never restricted, never Permanent).
4. **The degraded flag is observable**, not silent: it is surfaced in the status line (`daemon.rs:9203-9205`) between `membership_active_nodes` and the gossip block, with the ordering test updated (`daemon.rs:31948-31957`).

The one asymmetry worth stating plainly: after a degraded event the node keeps serving mesh traffic with mesh DNS unavailable (Untouched posture) until the next successful apply — that is the same zero-leak state finding 2 analyzed, re-entered deliberately instead of by restricting the node. Restriction was the wrong tool there: it *disabled the mesh* (availability loss, and pre-M3 it could escalate to Permanent on a flaky resolver) without making the DNS posture any safer than Untouched already is.

## Finding 4 — RACE: single bind, single owner; the probe is a real responder, not a mock; fail-closed unweakened

**VERDICT: REFUTED** (no double-bind, no data race, and `verify_loopback_resolver_live` retains every fail-closed property).

- **Single bind, single owner.** The non-Windows socket is bound and made non-blocking once, before `bootstrap()` (`daemon.rs:11905-11917`), wrapped in `Arc`, and the **same** `Arc<UdpSocket>` is installed as the probe servicer (`daemon.rs:11918-11922`) and drained by the main/restricted serve loops later (`recv_from` at `daemon.rs:12152` and `daemon.rs:12462`). The old main-loop bind was removed; there is exactly one `UdpSocket::bind` per platform path. On Windows the hoisted bind is `#[cfg(not(windows))]` and the `#[cfg(windows)]` block keeps its own retrying bind (10 attempts, 200 ms×(attempt+1) backoff, WSAEADDRINUSE SCM-restart race) at `daemon.rs:11938-11981` — Windows never had the loopback probe ("its DNS posture path has no loopback probe", comment `daemon.rs:11898-11904`), so nothing changes for it and both `cfg` blocks own a distinctly-scoped `dns_socket`.
- **No data race.** `DaemonRuntime` stays single-threaded (comment `daemon.rs:11983-11985`); bootstrap runs before the serve loop starts, so during bootstrap the *only* drainer of the shared socket is the servicer, invoked from inside the probe's wait loop (`servicer.service_once()` each iteration, `phase10.rs:4627`). After bootstrap the servicer is only ever called from a reconcile-time probe wait, which runs on the same thread as the serve loop — the two drainers never overlap. Even in the hypothetical overlap case, `recv_from` on a shared UDP socket from one thread at a time is kernel-safe and both drainers answer through the same `build_dns_response_with`, so a query would be answered identically regardless of which side drained it. `install_dns_probe_servicer` goes through `Phase10Controller::with_system` (`daemon.rs:10960-10962`), documented plumbing-only (no transitions, no audit) — it mutates only the `MacosCommandSystem.dns_probe_servicer` field (`phase10.rs:3751`, default `None` at 3799; `set_dns_probe_servicer` is a no-op on non-macOS system variants, `phase10.rs:6567-6572`).
- **The probe is genuinely unweakened.** `verify_loopback_resolver_live` (`phase10.rs:4578`) still sends the pinned probe query to `127.0.0.1:{port}` and requires, within the unchanged 2 s deadline, a reply of ≥12 bytes whose transaction ID matches the probe — otherwise `DnsApplyFailed("answered with a malformed DNS reply …")`; no answer by the deadline → `DnsApplyFailed("the loopback DNS resolver on 127.0.0.1:{port} did not answer: {err}")`; any other socket error → the same failure (`phase10.rs:4600-4640`). SERVFAIL still counts as live (pre-existing semantics: it proves a listener owns the port). The loop with a servicer polls at 50 ms instead of blocking 2 s per recv — a latency change to *how long we wait between recvs*, not to *whether an answer is required*.
- **The bootstrap probe now being answered by the servicer is not a self-test loophole.** The servicer answers through `build_dns_response_with` on the hoisted socket — the exact responder and the exact socket the daemon will serve DNS on for its lifetime (`DnsProbeServicer`, `daemon.rs:12606-12620+`; equivalence pinned by `bootstrap_probe_servicer_responder_matches_live_responder`, which asserts the servicer's wire answer is byte-identical to the runtime's). So "probe passes" still means precisely "this process owns 127.0.0.1:53535 and its hardened responder answers" — the property the check always verified. The negative test `macos_probe_servicer_cannot_answer_without_the_port` (servicer on an ephemeral port → probe fails closed, error names `127.0.0.1:53535`) and `macos_probe_answered_via_bootstrap_servicer` (unresolved state → SERVFAIL answer → Ok) pin both directions.

## Finding 5 — Other regressions in the 1047 changed lines

**VERDICT: REFUTED** (no security or correctness regression found; two non-security observations recorded).

Checked and clean:

- **`resolve_dns_ipv4_record` removal:** the method was replaced by the free function `resolve_dns_ipv4_record_in` (`daemon.rs:12723`); the only caller is `build_dns_response_with` at `daemon.rs:12697`. No dangling callers; response logic (out-of-zone → REFUSED, zone-missing/error → SERVFAIL, A-record lookup) is unchanged.
- **Status-line change:** the new `dns_scoped_apply_degraded` field is additive and its position is test-pinned (`daemon.rs:9203-9205`, `daemon.rs:31948-31957`).
- **Windows path untouched in behavior:** the windows `dns_socket` block retains the retrying bind (`daemon.rs:11938-11981`); `normalize_windows_dns_resolver_bind_addr` (`daemon.rs:13490-13503`) and the non-loopback bind rejection (`daemon.rs:13105`, tests at 35727+) are outside the diff.
- **Bootstrap failure paths unchanged:** any bootstrap apply error (including a FullyProtected DNS failure at bootstrap) still runs `restrict_recoverable` + `force_fail_closed_or_restrict("bootstrap_apply_failed")` (`daemon.rs:8918-8924`); the defer latch is only set on the `(Ok, Ok)` path.
- **Test-only plumbing:** `DryRunSystem.fail_on_with` (`phase10.rs` diff) is test infrastructure for the new failure-injection tests; production paths do not consume it.

Non-security observations (for the ledger; neither is introduced by M1–M4 as a *regression*):

1. **Generation aborts at the DNS arm on a degraded failure.** In `apply_dataplane_generation` the DNS arm sits after the tunnel/peers/routes stages and before the IPv6/exit-mode/assert-exit-policy stages (`phase10.rs:7363-7412`). A degraded scoped-DNS failure therefore leaves the later stages of that generation unapplied in that pass (the `?` aborts the apply; the controller does not mark the generation applied). The mesh dataplane that *did* apply is live — the "mesh unaffected" log claim holds for the tunnel — and the latch-armed next pass retries the entire generation, so this is the pre-existing single-apply, retry-whole-generation semantics, not a new partial-commit path. Worth knowing when reading logs: a degraded DNS event implies the following stages were skipped that pass.
2. **Cross-restart posture downgrade window.** A node restarting from FullyProtected into plain-client defer does not roll back the old pins/pf floor until the first reconcile (the ScopedResolverOnly arm rolls FullyProtected back first, `phase10.rs:5210-5212`). The window is ≤1 reconcile tick and strictly safer than the pre-fix behavior, where the same restart left the node failing its probe and heading into restriction. If this window ever matters operationally, the fix is a startup-time posture reconciliation, not a change to M1–M4.

---

## Conclusion

The M1–M4 split does what its commits claim and nothing more dangerous: FullyProtected protection remains in-bootstrap and unconditional (F1); the ScopedResolverOnly deferral trades at most one reconcile tick of Magic-DNS availability for a bootstrap that can actually complete, in a provably zero-leak `Untouched` intermediate state with a latch-guaranteed heal (F2); the M3 softening is conjunctively keyed to posture + error type, leaves the controller-side rollback and the daemon-side re-assert intact, and keeps FullyProtected and every non-DNS failure on the full fail-closed ladder (F3); the hoisted socket has a single owner and the probe keeps its 2-second, txid-checked, malformed-rejecting fail-closed contract (F4). **No confirmed security problem.**
