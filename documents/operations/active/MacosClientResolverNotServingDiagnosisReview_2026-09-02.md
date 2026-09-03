# Review — macOS Client Resolver Not Serving Diagnosis (2026-09-02)

**Status:** ADVERSARIAL REVIEW, docs-only. No code changed.
**Subject:** `MacosClientResolverNotServingDiagnosis_2026-09-02.md` (merged as `1d0f6486`) —
diagnosis of and recommended fix for the release-blocking macOS client
resolver-not-serving defect (`dns apply failed: the loopback DNS resolver on
127.0.0.1:53535 did not answer` → 5 reconcile failures → `RestrictionMode::Permanent`).
**All file:line citations below were re-anchored against this worktree's HEAD.**

## Verdict: ACCEPT-WITH-AMENDMENTS

The Q1 ordering diagnosis is **confirmed in full and is stronger than the original
states**: `build_dns_response` verifiably answers *every* parseable query, so the
probe deterministically passes once the serve loop drains — the defect is purely
invocation timing. The Q2 decoupling is **sound and is not a weakening**, provided
it gets its own error path (Finding 3).

But the **primary fix as written is NOT shippable**: deferring the DNS-posture
sub-apply out of bootstrap for *all* postures opens a real DNS leak window for
`FullyProtected` nodes (exit / full-tunnel). The deferral is safe for
`ScopedResolverOnly` only. `FullyProtected` must keep an in-bootstrap apply, which
requires making the serve path live during bootstrap (hoisted bind + in-apply
drain through the same `build_dns_response`). This is a correction to the fix
direction, not to the diagnosis: the diagnosis's §1.3 already predicted the
exit/full-tunnel exposure but its §3 option (1) does not actually close it.

## 1. Per-anchor verification

| # | Anchor (diagnosis citation) | Verdict | Re-anchored |
|---|---|---|---|
| 1 | DNS bind `daemon.rs:12209` | VERIFIED | `UdpSocket::bind(config.dns_resolver_bind_addr)` at `daemon.rs:12209`, nonblocking :12212 |
| 2 | Default bind addr `daemon.rs:444` | VERIFIED | `DEFAULT_DNS_RESOLVER_BIND_ADDR = "127.0.0.1:53535"` at `daemon.rs:444` |
| 3 | Probe port `linux_dns_protect.rs:188` | VERIFIED | `MACOS_SCOPED_RESOLVER_LOOPBACK_PORT: u16 = 53535` |
| 4 | Serve drain `daemon.rs:12353-12369` | VERIFIED | inner `dns_socket.recv_from` loop → `build_dns_response` → `send_to` at `daemon.rs:12353-12364`; **not role-gated** (plain client runs it identically) |
| 5 | `run_daemon` entry `daemon.rs:11712`; M1 recovery `:11789`; `DaemonRuntime::new` `:11804`; `bootstrap()` `:11812` | VERIFIED | all four confirmed at the cited lines |
| 6 | Bootstrap apply call `daemon.rs:8878`, `protected_dns: true` `:8889` | VERIFIED | `apply_dataplane_generation(...)` :8878; `protected_dns: true` :8889 |
| 7 | Restrict path `daemon.rs:8909-8912` | VERIFIED (drift ±6) | `restrict_recoverable("dataplane bootstrap apply failed: …")` :8910 + `force_fail_closed_or_restrict("bootstrap_apply_failed")` :8911 (plus the combined cleanup-Err arm :8914-8919) |
| 8 | Posture arm `phase10.rs:7270-7278` | VERIFIED | `if options.protected_dns {` :7270; `macos_dns_posture` :7275; `apply_dns_protection_for_posture(posture)?` :7276; `assert_dns_protection()` :7278 |
| 9 | Posture decision `phase10.rs:783-789` | VERIFIED | `ExitMode::Off` + !serve_exit ⇒ `ScopedResolverOnly`; never `Untouched` (doc comment :780-782) |
| 10 | Scoped apply `phase10.rs:4604`, probe first step `:4605` | VERIFIED | `apply_scoped_resolver_only` :4604, `verify_loopback_resolver_live()?` :4605 = FIRST statement, before any mutation |
| 11 | Probe definition `phase10.rs:4532-4573` | VERIFIED | `verify_loopback_resolver_live` :4532; 2 s read timeout; `recv` error rendered `"the loopback DNS resolver on 127.0.0.1:53535 did not answer: {err}"`; reply accepted iff `len >= 12` and txid bytes match |
| 12 | `rollback_after_failed_apply` `phase10.rs:4578-4583` | VERIFIED | exact lines |
| 13 | Full protection `apply_dns_protection` `phase10.rs:4961`, probe `:4969` | VERIFIED | probe :4969 first statement; pf rules :4971; live-floor verify :4979; backup write before first mutation :5052; per-service pins :5054-5067; resolv.conf :5083-5090; scoped file :5103-5110; `dns_posture = FullyProtected` :5111 |
| 14 | Reconcile re-apply predicate `daemon.rs:10440-10448` | VERIFIED | `will_apply_generation` disjunction incl. `RestrictionMode::Recoverable` and `dns_posture_reassert_pending` :10448 |
| 15 | Reassert latch `daemon.rs:4756` | VERIFIED | field `dns_posture_reassert_pending: bool` :4756; set by S1 :10835; cleared after apply :10607 |
| 16 | Failure increment `daemon.rs:10695-10701` | VERIFIED (drift ±1) | `reconcile_failures.saturating_add(1)` at :10696/:10704/:10714 (apply-Err / cleanup-Err arms of the reconcile apply) |
| 17 | `DEFAULT_MAX_RECONCILE_FAILURES` `daemon.rs:552`; interval `:498` | VERIFIED | `= 5` :552; `DEFAULT_RECONCILE_INTERVAL_MS = 1_000` :498 |
| 18 | `promote_to_permanent_if_over_limit` `daemon.rs:10980-10987` | VERIFIED | exact lines |
| 19 | S1 re-assert `daemon.rs:10800-10840` | VERIFIED | `maybe_assert_dns_posture` :10800-10837; **note the `controller.dns_protected()` gate :10819** (material to Finding 4) |
| 20 | Zone loads `daemon.rs:8931` / `:10664` | VERIFIED | `refresh_dns_zone_state` (def :5544) called in bootstrap's post-apply path and reconcile's success arm :10664 — after the applies, as stated |
| 21 | Error rendering `phase10.rs:462` | VERIFIED | `SystemError::DnsApplyFailed(message) => write!(f, "dns apply failed: {message}")` |
| 22 | Untouched-is-only-scoped-file rationale `phase10.rs:5091-5099` | VERIFIED | "`/etc/resolver/<domain>` is the mechanism the OS honors … the ONLY route from the OS resolver to the resolver's :53535 bind" |
| 23 | Scoped/Untouched doc comments `phase10.rs:755-763` | VERIFIED | ScopedResolverOnly: "the machine's own DNS is untouched"; Untouched: "never returned by `macos_dns_posture`" |
| 24 | Apply-time-probe test `phase10.rs:17439-17449` | VERIFIED (drift −3) | `macos_scoped_posture_fails_closed_without_live_resolver` :17436, assertions :17439-17450 |
| 25 | Windows bind retry `daemon.rs:11838-11869`; `:53` normalize `:13268-13281` | VERIFIED (drift +3) | retry loop :11838+; `normalize_windows_dns_resolver_bind_addr` :13268-13284 |
| 26 | Linux nft redirect `linux_dns_protect.rs:20-24` | VERIFIED | module doc :18-24 (`:53`→`:53535` redirect, proven live on `debian-headless-1`) |
| 27 | `build_dns_response` `daemon.rs:12459-12520` | VERIFIED — **see §2, the load-bearing check** | every arm returns `Some` |

No citation in the diagnosis was found WRONG. Two drifted by ≤6 lines; both
re-anchored cleanly. The diagnosis's line-number caveat ("read from the working
tree at diagnosis time") was justified.

## 2. The load-bearing check: does `build_dns_response` always answer?

**YES — confirmed by reading the function in full** (`daemon.rs:12459-12520`).
Every reachable arm returns `Some`:

- unparseable request → `Some(FORMERR)` (:12471-12476);
- qname outside the managed zone → `Some(REFUSED)` (:12478-12484);
- non-IN class → `Some(REFUSED)` (:12485-12491);
- signed zone absent or in error → `Some(SERVFAIL)` (:12492-12498);
- `QTYPE=A` → `Some(NOERROR+answer)` or `Some(NXDOMAIN)` (:12499-12506);
- `QTYPE=AAAA` → `Some(NOERROR, empty)` (:12508-12513);
- any other qtype → `Some(NOERROR, empty)` (:12515-12519).

The probe (`phase10.rs:4535-4538`) sends a well-formed single-question
`rustynet. IN A` query with txid `0x524e` and accepts any reply of ≥12 bytes
whose first two bytes echo the txid (:4567-4571). It does not inspect the rcode.
**Therefore the probe WILL be answered — REFUSED, SERVFAIL, or NOERROR all pass —
the moment the serve loop at `daemon.rs:12353` drains even one packet.** The
"ordering only" conclusion stands; no zone, role, or capability is required.
The `None` return of `build_dns_response` is unreachable for a well-formed
query (`parse_dns_question` failures are caught at :12468-12477 and rendered).

**Consequence:** the diagnosis's causal chain (probe → ICMP port-unreachable →
`DnsApplyFailed` → rollback → ladder → Permanent) is correct end-to-end, and the
probe/rollback/three-state machinery needs no modification — only its invocation
timing.

## 3. Make-or-break: is the deferral safe? — **NO for `FullyProtected`; YES for `ScopedResolverOnly`**

This is the security crux, and the primary recommendation as written gets it
wrong.

### 3.1 The window is real

The DNS arm sits at a specific point in `apply_dataplane_generation`
(`phase10.rs`): backend routes :7257 → NAT :7261-7267 → **DNS posture :7270-7279**
→ IPv6 hard-disable :7282 → **`set_exit_mode` :7286**. For a `FullyProtected`
node, the DNS posture sub-apply is the ONLY thing that installs:

- the pf DNS-block floor and its live-ruleset verification (:4971, :4979),
- the per-service loopback pins (:5054-5067),
- the `/etc/resolv.conf` rewrite (:5083),
- the scoped file (:5103).

All of the machine's general DNS protection lives inside that one sub-apply. The
macOS M1 startup recovery (`daemon.rs:11789`) *restores* state; it does not
protect. The `force_fail_closed_or_restrict` pf anchor (:10963) is a reaction to
failure, not a startup floor. If the DNS sub-apply is deferred out of bootstrap,
then between "bootstrap returns (routes/NAT applied, main loop serving)" and
"first reconcile pass applies the posture" there is a window of at least
`DEFAULT_RECONCILE_INTERVAL_MS = 1000 ms` (`daemon.rs:498`) plus probe/apply
duration during which a full-tunnel / exit node **resolves general DNS through
its LAN resolvers with no pf floor and no pins while the tunnel dataplane is
already up**. `Requirements.md:186` ("VPN operating modes requiring protected
routing must fail closed for traffic **and DNS**") and `SecurityMinimumBar.md` §8
apply to exactly this posture. That is a leak window, not a delay.

Worse: the window is retry-amplified on a sick node, and it is the *same* code
path (`protected_dns: true`, `daemon.rs:8889`) that the exit-serving adapter
cells will drive — so the deferral would trade a deterministic client failure
for a silent, unmeasured protected-mode exposure.

### 3.2 Why the client deferral is safe

For `ScopedResolverOnly`, the sub-apply's ONLY mutation is the single
`/etc/resolver/rustynet` file (`phase10.rs:755-759`, :4604-4631 — no pf, no
pins, no resolv.conf). The probe is the first statement (:4605); a failure
mutates nothing and `rollback_after_failed_apply` (:4578) restores `Untouched`,
which is the machine's cold-start state anyway. Deferring costs at most ~1 s of
Magic-DNS availability after daemon start — a capability delay indistinguishable
from "daemon not started yet", which is already an accepted state. General DNS
is untouched throughout; nothing leaks *through* Rustynet policy. No
higher-precedence requirement (Requirements :90/:186, SMB §8 are
protected-DNS/protected-routing scoped) is engaged by a plain client's scoped
file timing.

### 3.3 Strictest-secure resolution (amendment to the primary fix)

**Posture-split deferral:**

- **`ScopedResolverOnly`**: defer the DNS sub-apply out of bootstrap into the
  first reconcile pass, reusing `dns_posture_reassert_pending`
  (`daemon.rs:4756`/`:10448`/`:10607`) so the S1 ladder owns retries — the
  diagnosis's option (1), adopted verbatim *for this posture only*.
- **`FullyProtected`**: the sub-apply STAYS inside bootstrap. To make it
  satisfiable, the serve path must be live during bootstrap; a bounded-retry
  probe against the current bind ordering cannot work (the diagnosis's §1.2 is
  correct — the bind at `daemon.rs:12209` happens only after `bootstrap()`
  returns at :11812, so intra-apply retries see the same dead port). The minimal
  strict change, preserving one hardened execution path:
  1. **Hoist the `dns_socket` bind** (`daemon.rs:12209`) above
     `runtime.bootstrap()` (:11812) in `run_daemon`, storing the socket so both
     bootstrap-time probe servicing and the main loop use the same socket.
  2. **Service probe queries through the same answering logic**: after the probe
     sends its query, drain the shared socket synchronously (nonblocking
     `recv_from`) and dispatch through `build_dns_response` (`daemon.rs:12459`)
     — the identical function the main loop uses — until the probe's txid is
     seen or the existing 2 s timeout expires. No second DNS implementation, no
     fallback branch: it is the same socket, the same parser, the same
     responder, merely drained at a second point in time.
  3. Failure still rolls back fail-closed and climbs today's ladder unchanged.

  (Acceptable alternative, rejected as more invasive: defer `FullyProtected` DNS
  too, but hold the node fully fail-closed — no dataplane opened, exit mode not
  set — until the first reconcile applies DNS *then* `set_exit_mode` in order.
  This preserves the protected ordering but restructures bootstrap completion
  and every validator that assumes it. The hoisted-bind variant is smaller and
  keeps today's in-bootstrap semantics for the protected posture.)

This also *corrects the diagnosis's §3 option (2)*: its claim that binding
before bootstrap "buys nothing over (1) security-wise" is wrong — for
`FullyProtected` it buys exactly the thing that matters, an in-bootstrap DNS
posture for protected routing. And its §1.2 sentence "no intra-apply
bounded-retry can fix it" is true only under the *current* bind ordering; with
the hoisted bind plus in-apply drain, the probe's existing 2 s timeout *becomes*
the bounded retry.

## 4. Numbered findings

**F1 (correct, adopted):** Q1 ordering diagnosis — verified in full, including
the always-answer property of `build_dns_response` (§2 above). No amendment.

**F2 (correct, adopted):** Q2 — a `ScopedResolverOnly` apply failure must not
take down the node. Not a weakening (§5 below). Amended: needs its own error
path — see F4.

**F3 (CORRECTED):** the primary deferral must be posture-split (§3.3). Deferring
`FullyProtected` DNS out of bootstrap opens a ≥1 s unprotected-DNS window on a
tunnel-up node — a genuine leak under `Requirements.md:186` / SMB §8. Exact
amendment text: *"Option (1) applies to the `ScopedResolverOnly` posture only.
For `FullyProtected`, the DNS sub-apply remains in `apply_dataplane_generation`
at bootstrap; the daemon hoists the `dns_socket` bind above
`runtime.bootstrap()` and services the bootstrap-time probe by draining that
socket through `build_dns_response` under the probe's existing 2 s bound. The
probe, the all-or-nothing rollback, and the three-state decision are preserved
verbatim for both postures; only the scoped posture's invocation timing moves."*

**F4 (new — decoupling mechanics):** the Q2 decoupling as described ("restricts
the DNS posture… surfaced via `last_reconcile_error` + S1 ladder") has no
implementation site: today ANY apply `Err` lands in the (Err) arm
(`daemon.rs:10696-10701`) which increments `reconcile_failures`, calls
`restrict_recoverable` + `force_fail_closed_or_restrict`, and after 5 passes
`promote_to_permanent_if_over_limit` (:10980) — i.e. the node restricts exactly
as before. The decoupling requires a **distinct branch**: for a
`ScopedResolverOnly` deferred-apply failure, record `last_reconcile_error`, set
`dns_posture_reassert_pending` (so the :10448 predicate re-applies next pass,
S1-cadence), do **not** increment `reconcile_failures`, do **not** call
`restrict_recoverable`/`force_fail_closed_or_restrict`, and persist an explicit
degraded flag so the `DnsFailclosed` validator fails loud (a silently-absent
scoped file must not read as "pass"). `FullyProtected` failures keep the
existing full ladder byte-for-byte. Exact amendment text: *"The deferred scoped
apply runs as its own step whose failure takes the DNS-degraded branch, never
the apply-failure restriction ladder; the ladder remains the sole path for
`FullyProtected` failures."*

**F5 (confirmed, no change):** the rejection of client-`Untouched` is correct
and load-bearing: `/etc/resolver/<domain>` is the only OS route to the
loopback resolver (`phase10.rs:5091-5099`), and `Untouched` would leak
`*.rustynet` query names to the LAN resolver — the exact gap the scoped posture
exists to close (:755-759).

## 5. Is the Q2 decoupling a weakening?

**No — it is a capability gap with full surfacing, and it cannot mask a leak:**

- **Not a leak:** the probe precedes every mutation (:4605/:4969), so a failed
  scoped apply leaves the node at `Untouched` — machine DNS untouched, no pins,
  no resolv.conf rewrite, no pf floor, nothing pointing at a dead listener.
  General resolution behaves exactly as with the daemon stopped. The mesh
  dataplane (the fail-close domain of Requirements :186 §3.4) is unaffected.
  The only gap is `*.rustynet` name resolution (Magic DNS down) — a capability,
  not an egress path outside policy.
- **Surfaced:** `last_reconcile_error` records the failure each pass, the
  reassert latch re-applies at S1 cadence, and — with F4's amendment — a
  persisted degraded flag keeps the `DnsFailclosed` stage red instead of
  silently absent.
- **Cannot mask a real leak:** the decoupling is keyed on the *posture decided
  from the generation* (`macos_dns_posture`, :7275), never on observed state —
  a node that is actually `FullyProtected` cannot be talked into the lenient
  branch, and any `FullyProtected` failure still restricts. The rollback
  guarantee (probe-before-mutation) means the lenient branch's worst case is
  "no scoped file", never "partial posture".

## 6. Interaction check (deferral × S1 / M1 / Gap A)

- **S1 re-assert** (`maybe_assert_dns_posture`, `daemon.rs:10800-10837`): gated
  on `controller.dns_protected()` (:10819). The scoped posture sets
  `dns_protected = false` (`phase10.rs:4632`), so the periodic drift-assert
  never fires for clients — the reassert **latch** (:10448/:10607/:10835) is the
  only client heal path, which is exactly what the deferral reuses. Correct as
  designed; do not "fix" the gate.
- **M1 startup DNS recovery** (`daemon.rs:11789`): runs before `bootstrap()`
  (:11812) and therefore before any deferred first-pass apply — ordering
  preserved. A deferred `FullyProtected` apply (under the §3.3 alternative)
  would still sit after recovery; under the adopted hoisted-bind variant this
  is moot because the protected apply never moves.
- **Gap A post-restart signed-state refresh:** the first reconcile evaluates
  `will_apply_generation` (:10440) *before* the traversal refreshes by design
  (QH-04 comment :10436-10443), and the apply branch itself reloads state before
  applying — so the deferred posture decision naturally observes refreshed
  state. The diagnosis's ordering requirement ("refresh must complete BEFORE the
  deferred posture decision") is satisfied structurally by running the deferred
  apply inside the existing apply branch; it must not be pulled out ahead of it.

## 7. Offline-testable core for the chosen fix

- `phase10.rs` (`DryRunSystem` / `MacosCommandSystem` op recording):
  1. `apply_dataplane_generation(protected_dns: true, exit_mode: Off, serve_exit: false)`
     at bootstrap **emits no DNS ops** (no `DNS_FILE_SELECTOR_MACOS_RESOLVER_APPLY`,
     no `networksetup` writes) — scoped deferral.
  2. The same call with `exit_mode: FullTunnel` (or `serve_exit_node: true`)
     **still emits the full DNS sequence** (pf, floor verify, backup, pins,
     resolv.conf, scoped file) — protected stays in-bootstrap.
  3. First-pass deferred scoped apply emits exactly the scoped-file op, after
     routes/NAT ops.
  4. Scoped apply failure (probe unreachable) → posture stays `Untouched`,
     zero mutations (existing `macos_scoped_posture_fails_closed_without_live_resolver`
     :17436 moves to the new invocation surface and keeps passing).
- `daemon.rs` (state-machine tests):
  5. A scoped deferred-apply failure does **not** increment `reconcile_failures`,
     does not enter `RestrictionMode::Recoverable`, sets
     `dns_posture_reassert_pending`, and records `last_reconcile_error`.
  6. A `FullyProtected` deferred-path failure (or bootstrap protected failure)
     still increments and restricts — the ladder test suite (:18293-18651)
     extended with the posture split.
  7. Latch lifecycle: set on failure → next pass re-applies → cleared on success
     (:10607) → degraded flag cleared only by a successful scoped apply.
- Probe/hoist (if F3 adopted): unit test that a bootstrap-time probe is answered
  when the hoisted socket is drained through `build_dns_response` (loopback
  bind in-test, mirroring the existing probe tests).

**Live proof (rank-1 harvest):** a `--node` run with `macos-utm-1` as plain
client where BOTH `macos-utm-1/DnsFailclosed` and `macos-utm-1/MeshStatus`
return to pass, the daemon log shows the scoped apply succeeding after the serve
loop is live, and `RestrictionMode::None` persists — verified against the
stage's own report artifacts, not the matrix row (§10.9 rule). The exit-serving
adapter cells then prove the `FullyProtected` in-bootstrap path on a live
listener (closing the §1.3 prediction).

## 8. Considered, no defect

- **`build_dns_response` returning `None`:** unreachable for the probe's query;
  parse failures render FORMERR (:12468-12477). The always-answer property holds.
- **Probe accepting REFUSED/SERVFAIL:** by design — it asserts *a live
  listener*, not zone correctness; zone health is separately observable
  (`refresh_dns_zone_state`, diagnosis §5.1 `dig` probe). Tightening the probe
  to require NOERROR would couple dataplane bring-up to bundle delivery — a
  worse failure mode.
- **Binding in the apply path instead of hoisting:** would duplicate the bind
  (two owners of one addr) or require socket hand-off anyway; hoisting is the
  smaller change.
- **Making `ScopedResolverOnly` set `dns_protected = true`:** would activate the
  S1 drift-assert for clients (:10819 gate), whose asserts assume the full
  posture's invariants (pf floor, pins) — wrong for a pf-less posture. The latch
  is the correct client mechanism.
- **Reconcile-time applies:** unaffected by the defect (serve loop already live)
  and untouched by the fix; no change warranted there.
- **Windows/Linux exposure:** none — Windows probes not used and bind normalized
  to `:53` (`daemon.rs:13268-13284`); Linux answers behind the nft redirect
  (`linux_dns_protect.rs:18-24`). The fix is macOS-scoped; no cross-platform
  regression surface.
- **Diagnosis's line-drift caveat:** legitimate — two citations drifted ≤6 lines
  on this tree; none changed meaning.

## 9. Amendment (2026-09-03): M2 deferral removed — scoped posture applies in-bootstrap

The §5 fix (M2) deferred the `ScopedResolverOnly` DNS posture out of bootstrap to
the first reconcile. That deferral is now REMOVED: bootstrap applies the scoped
posture in-place, because the `validate_baseline_runtime` validator runs
immediately after `enforce_baseline_runtime` — inside the former deferral window
— so a plain macOS client failed `DnsFailclosed` validation with
`/etc/resolver/rustynet` still absent.

This is safe because M1 (probe hoist + `DnsProbeServicer`) already answers the
bootstrap probe for ANY posture, so the scoped apply's
`verify_loopback_resolver_live` gate passes during bootstrap and the resolver
file is written before validation runs. `FullyProtected` behavior is unchanged
(in-bootstrap apply, full restrict-on-failure ladder).

Failure handling now mirrors the reconcile path: a scoped-posture bootstrap
`DnsApplyFailed` is availability-only — the daemon logs the degradation, sets
`dns_scoped_apply_degraded` + `dns_posture_reassert_pending` (reconcile retries
and clears both on success), and does NOT restrict; the mesh is unaffected since
the probe precedes every mutation (posture stays untouched on failure). A
`FullyProtected` bootstrap DNS failure still runs the full
`restrict_recoverable` + `force_fail_closed_or_restrict` ladder, and the
cleanup-failure arm keeps full restrict (key custody dominates).

The `defer_scoped_dns_posture` flag is retained in `ApplyOptions` (legacy
caller-unset path; both daemon call sites now pass `false`); the
`bootstrap_defers_scoped_dns_posture_to_first_reconcile` and
`bootstrap_deferred_scoped_posture_emits_no_dns_ops` tests were replaced by
applies-in-bootstrap and retained-defer-flag tests, plus new
degrades-without-restricting / still-restricts bootstrap failure tests.
