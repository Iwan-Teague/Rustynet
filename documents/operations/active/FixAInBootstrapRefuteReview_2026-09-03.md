# Fix (A) In-Bootstrap Scoped DNS Posture — Adversarial Refute Review

Date: 2026-09-03
Change under review: merge `c53fb247` (parents `b108c201` + `b26c9b1c`; real code change in `61b303ca` "Apply scoped DNS posture in bootstrap; degrade on scoped failure", plus `b26c9b1c` "Format rustynetd test code").
Review basis: real code read at HEAD `bc438c7e` in `crates/rustynetd/src/daemon.rs` and `crates/rustynetd/src/phase10.rs`. All line references below are to that tree.

**Bottom line: no CONFIRMED problems. All five questions REFUTED (the change is safe). Three precision observations recorded at the end — none is a defect, none requires code change.**

---

## Q1 — FullyProtected still applies full DNS protection in-bootstrap and keeps the full restrict ladder; the degraded branch is unreachable for it

**VERDICT: REFUTED (safe).**

- The bootstrap degraded branch is gated on the posture **decided from the generation's inputs, never observed state**: `applied_dns_posture` is `Some(macos_dns_posture(bootstrap_exit_mode, serve_exit_node))` on macOS and `None` off-macOS (`daemon.rs:8894-8898`). `bootstrap_exit_mode` is derived purely from role/auto-tunnel/desired state (`daemon.rs:8883-8893`), the same values passed into `ApplyOptions` (`daemon.rs:8912-8917`), and the engine decides the posture from those **same** `options.exit_mode` / `options.serve_exit_node` (`phase10.rs:7395`). Daemon and engine therefore cannot disagree about which posture ran.
- The degraded branch additionally requires the error to be exactly `Phase10Error::System(SystemError::DnsApplyFailed(_))` (`daemon.rs:8934-8941`). A `FullyProtected` node yields `Some(DnsPosture::FullyProtected)` (`phase10.rs:801-807`: `FullTunnel` or `serve_exit_node` → `FullyProtected`), which fails the gate and falls to the `else` arm: `restrict_recoverable(format!("dataplane bootstrap apply failed: {err}"))` + `force_fail_closed_or_restrict("bootstrap_apply_failed")` + `return` (`daemon.rs:8955-8959`) — byte-for-byte the pre-change ladder. The cleanup-failure arms are untouched (`daemon.rs:8961-8974`).
- Full protection is still applied **in-bootstrap**: the `FullyProtected` dispatch runs `apply_dns_protection` (`phase10.rs:5229`), the complete hardened sequence — probe → pf floor → live-floor verify → per-service pins → `resolv.conf` → scoped file, all-or-nothing with rollback on any post-mutation failure (`phase10.rs:5058-5210`) — followed by `assert_dns_protection` (`phase10.rs:7412`).
- Off-macOS, `applied_dns_posture` is `None`, so every error takes the restrict ladder exactly as before; the engine's posture default forwards every posture to full protection there (`phase10.rs:701-706`), which is over-protecting, never under-.
- Negative control test exists: `bootstrap_fully_protected_dns_apply_failure_still_restricts` asserts `RestrictionMode::Recoverable` and no degraded flag.

## Q2 — Degraded bootstrap branch leaves the node zero-leak (no half-applied scoped state), and the latch re-arms for reconcile retry

**VERDICT: REFUTED (safe).**

- The scoped sub-apply is `apply_scoped_resolver_only` (`phase10.rs:4701-4731`). The **only mutation** is the single `/etc/resolver/rustynet` write (`phase10.rs:4719-4727`), and the loopback-resolver probe **precedes it** (`phase10.rs:4702`). Every earlier failure path is read-only or a refusal: service enumeration (`phase10.rs:4703-4705`), per-service DNS read (`phase10.rs:4707-4709`), and the stranded-loopback-pin refusal (`phase10.rs:4711-4716`) — none mutates anything, so the posture stays `Untouched` (the pre-install, machine-DNS-untouched state). The write itself goes through the privileged helper's fixed-path/fixed-content builtin, so a failure installs no partial file.
- Engine-level consistency: the `DnsApplied` stage marker is pushed only after a successful sub-apply (`phase10.rs:7410-7411`), so on a DNS failure the generation rollback has no DNS stage to unwind. If the apply succeeds but the subsequent assert fails, the marker **is** present and the generation rollback unwinds DNS back to `Untouched` (`phase10.rs:7208-7225`).
- The degraded branch re-arms the heal latch and records the durable degraded flag (`daemon.rs:8952-8954`), and the first reconcile pass re-applies the **whole** generation (see Q3), clearing `dns_scoped_apply_degraded` on success (`daemon.rs:10752`). Test `bootstrap_scoped_dns_apply_failure_degrades_without_restriction` proves latch + degraded flag + operator-surfaced error + heal-on-next-reconcile with zero reconcile-failure accounting.
- Zero-leak framing: with the scoped file absent, `*.rustynet` names resolve via the LAN resolver during the degraded window — but that is exactly the pre-install baseline and exactly the window the retired M2 deferral had anyway (bootstrap → first reconcile tick). The change shrinks that window on success (resolver live before `validate_baseline_runtime`) and does not widen it on failure.

## Q3 — Generation-abort on scoped DNS failure: later stages skipped that pass; is that a leak; does retry re-apply the whole generation

**VERDICT: REFUTED (safe).**

- Ordering in `apply_generation_stages`: DNS arm (`phase10.rs:7390-7414`) precedes IPv6 hard-disable (`phase10.rs:7416-7419`), `set_exit_mode` (`phase10.rs:7421-7422`), and `assert_exit_policy` (`phase10.rs:7424-7427`). A DNS failure via `?` at `phase10.rs:7410` skips those stages **for that pass** — real, by design.
- For a plain `ScopedResolverOnly` client the IPv6 hard-disable **is** engaged (its only gate is `!options.ipv6_parity_supported`, and bootstrap passes `ipv6_parity_supported: false`, `daemon.rs:8911`), so it is genuinely skipped on the failed pass. This is **not a leak**: the engine does not leave the partial generation exposed. `apply_dataplane_generation` catches the stage error and runs `rollback_generation_best_effort(applied_stages, RollbackIntent::FailClosed)` + `force_fail_closed("apply_failed")` (`phase10.rs:7208-7225`) — peers/routes/routes-bypass are unwound and the controller lands in `FailClosed`, i.e. the node ends **closed**, not exposed. Skipped hard-disable over an already-rolled-back dataplane is the pre-rustynet posture, and `assert_exit_policy` failing to run cannot create exposure when nothing is applied.
- Retry re-applies the **whole generation**, not a DNS-only patch: `dns_posture_reassert_pending` is a `will_apply_generation` disjunct (`daemon.rs:10496-10499`), controller `FailClosed` is another disjunct (`daemon.rs:10491`), and the latch fires the full `apply_dataplane_generation` with identical options (`daemon.rs:10639-10659`). The latch is cleared before the match (`daemon.rs:10672`) and re-armed only on another scoped failure (`daemon.rs:10792`), so there is no stuck-latch and no double-fire. First tick after bootstrap heals (1 s default cadence, `daemon.rs:498`).

## Q4 — Did retiring the deferral drop or weaken anything M1/M3 needs

**VERDICT: REFUTED (safe).**

- M1 bootstrap machinery intact and correctly ordered in `run_daemon`: `run_startup_dns_recovery` (`daemon.rs:11908`) → `install_dns_probe_servicer` (`daemon.rs:11957`, struct at `daemon.rs:12644`, installer at `daemon.rs:10998`) → `runtime.bootstrap()` (`daemon.rs:11961`). The servicer is installed **before** bootstrap, which is precisely what lets the in-bootstrap probe succeed for any posture.
- The probe itself is untouched by this change: `verify_loopback_resolver_live` (`phase10.rs:4592-4670`) keeps the servicer-drain poll loop (50 ms poll against the 2 s deadline, `phase10.rs:4628-4643`); it does not appear anywhere in the `61b303ca` diff.
- The reconcile-time M3 degraded path is byte-identical before and after: `daemon.rs:10763-10801` is absent from the diff; only the bootstrap block (`daemon.rs:8883-8975` region) and tests changed in `daemon.rs`.
- The engine-level deferral path is retained and still tested (`defer_flag_scoped_posture_emits_no_dns_ops`, `phase10.rs:11305+`), and a repo-wide grep shows exactly two `defer_scoped_dns_posture` references outside `phase10.rs` — both call sites, both `false` (`daemon.rs:8917`, `daemon.rs:10657`). No caller sets `true`; the retained branch is dead-in-production but live-in-tests, matching the commit message.

## Q5 — Any other regression in the diff

**VERDICT: REFUTED (no regression found).**

- `b26c9b1c` is pure rustfmt of one test call site (5 lines in `bootstrap_scoped_dns_apply_failure_degrades_without_restriction`); no behavior change.
- The renamed tests strengthen rather than weaken the assertions: `bootstrap_applies_scoped_dns_posture_in_bootstrap` now requires `apply_dns_protection` **and** `assert_dns_protection` during bootstrap, no heal latch on success, and no latch after reconcile (`daemon.rs:18526+`); the scoped-failure test asserts no restriction, no reconcile-failure accounting, latch + degraded flag + operator error, then full heal; the FullyProtected negative control asserts `RestrictionMode::Recoverable`. No pre-existing assertion was removed or loosened.
- The `ApplyOptions` field doc was rewritten accurately (`phase10.rs:401-421`): it now states no caller sets the flag, the skip emits no ops, and `FullyProtected` is never deferred — all verified true against the code.
- Posture classification uses the decided generation posture at both call sites (bootstrap `daemon.rs:8894`, reconcile `daemon.rs:10634`), never inferred from observed state — the review §5 invariant holds.

## Observations (no action required)

1. **Comment precision, bootstrap degraded branch**: "the mesh is ALIVE here" (`daemon.rs:8928`, `8947-8951`) is imprecise — the engine has already rolled the generation back and fail-closed the controller (`phase10.rs:7216-7218`), so the node is mesh-less for one reconcile tick until the latch-driven re-apply lands. The direction is safe (closed, not exposed) and the availability-only classification still holds, but the comment overstates liveness.
2. **Comment precision, probe-precedes-mutation**: for the sub-case where the scoped apply **succeeds** and the following `assert_dns_protection` fails (also a `DnsApplyFailed`, `phase10.rs:5239-5260`), the posture was mutated and then unwound by the generation rollback — "the probe precedes every mutation, so the posture is already rolled back to Untouched" is true via the generation rollback, not via probe-ordering alone. Outcome identical (Untouched + degraded + retry), so no defect.
3. **Retry cadence on persistent scoped failure**: a permanently failing scoped posture (e.g. unresolvable stranded pins) re-arms the latch every pass, producing a full generation apply+rollback every 1 s tick. This is inherited verbatim from the pre-existing M3 reconcile behavior (`daemon.rs:10792`), not introduced here; the bootstrap branch merely arms the same single latch earlier. Worth a future backoff consideration, out of scope for this change.

## Verification

Docs-only review — no code modified. Gate run: `cargo fmt --all -- --check` (clean). Code gates are unchanged from the reviewed merge; the five macOS-gated tests named above (`bootstrap_applies_scoped_dns_posture_in_bootstrap`, `bootstrap_scoped_dns_apply_failure_degrades_without_restriction`, `bootstrap_fully_protected_dns_apply_failure_still_restricts`, `scoped_posture_applies_in_bootstrap_when_not_deferred`, `defer_flag_scoped_posture_emits_no_dns_ops`) encode the behavior this review verified by reading.
