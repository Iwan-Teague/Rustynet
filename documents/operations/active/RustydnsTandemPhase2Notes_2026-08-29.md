# RustyDNS Tandem Phase 2 Notes — D-6b Managed-DNS Handoff Control-Plane Wiring (2026-08-29)

Phase 2 of the tandem program (design:
`RustydnsTandemIntegrationDesign_2026-08-27.md`; phase 1:
`RustydnsTandemPhase1Notes_2026-08-28.md`). This phase delivers the
**control-plane decision wiring only**: it decides, per client, whether the
managed-DNS resolver assignment hands out the RustyDNS mesh endpoint. It does
not implement the exit-side port-53 redirect (D-6c), any per-OS dataplane,
RustyDNS process management, or any cross-repo call.

## 1. What D-6b delivers

New domain-layer module `crates/rustynet-control/src/managed_dns_handoff.rs`
(transport-agnostic, no I/O, no backend or WireGuard types):

- `managed_dns_handoff_decision(ManagedDnsHandoffInput) -> ManagedDnsHandoffDecision`
  — the single resolver-assignment decision point. It consumes the
  post-reconcile `TandemTogglePhase` from the phase-1 state machine plus the
  abstract inputs that machine already models (accepted `TandemScope`,
  client NodeId, `ExitAssignment`, `ReadinessObservation`) and one new
  abstract input: the RustyDNS mesh endpoint.
- `ManagedDnsHandoffDecision`:
  - `Handoff { endpoint, mode }` — hand the RustyDNS mesh IP to the client as
    its managed mesh resolver. Both v1 modes (`managed`,
    `managed_redirect`) hand off the same endpoint; the redirect variant only
    adds the exit-side diversion, which is D-6c and deliberately not decided
    here.
  - `Contained { reason }` — selected DNS is deliberately unavailable with an
    operator-visible `TandemReasonCode`. Never a fallback to a non-tandem or
    pre-tunnel resolver (design invariant 7; "the blocker follows the
    device").
  - `NoHandoff` — no tandem resolver assignment applies (signed OFF,
    prepare-only phases, draining, or client not selected by an explicit
    NodeId scope). The ordinary Rustynet DNS posture applies.
- `ManagedDnsEndpoint` — abstract v1 endpoint: mesh IPv4 address only, port
  fixed at `TANDEM_DNS_RESOLVER_PORT = 53`, transports fixed at `{udp, tcp}`
  by the signed capability contract (design §5.3).
- `MeshIpv4Prefix` — caller-supplied signed mesh assignment range
  (`const fn new` rejects prefix length > 32 and network addresses with host
  bits set). The endpoint must fall strictly inside it.

## 2. Fail-closed decision order (deterministic; earlier arms win)

1. `Off` / `ResidueError` → `NoHandoff`.
2. `PreparingContained` / `Prepared` → `NoHandoff` — a prepare intent is
   authorization to prepare local contained state only and "cannot advertise
   a resolver" (design §5.2).
3. `Draining` → `NoHandoff` — new handoffs are gone (design §5.1).
4. `RuntimeContained { reason }` → `Contained { reason }` — carries the
   recorded containment reason.
5. `Active(mode)` predicate ladder, every failure containing:
   1. No accepted scope known → `Contained(SIGNED_POLICY_INVALID)`.
   2. Empty/blank client NodeId → `Contained(UNKNOWN_CLIENT)`.
   3. Readiness not `Ready` → `Contained(contain_reason())` (the phase-1
      staleness/auth/passthrough mapping). Readiness is evaluated before
      selector and endpoint predicates so the surfaced reason is service
      health, not a selector artifact.
   4. Scope selection: `AllClientsUsingExit` requires
      `ExitAssignment::ProvenSameExit` (invariant 3); `NodeIds` scope
      requires the client to be listed AND the same proven-exit proof.
      Listed-but-unproven → `Contained(ASSIGNMENT_MISMATCH)`. A client not
      listed by an explicit NodeId scope is **not contained** — it was never
      selected, so its ordinary posture applies (`NoHandoff`).
   5. Endpoint `None` (unknown/not carried) → `Contained(RUSTYDNS_UNREACHABLE)`.
   6. Mesh prefix `None` (cannot prove containment) or endpoint outside the
      signed mesh range (loopback, link-local, LAN, and public classes are
      all outside a real mesh range) → `Contained(ASSIGNMENT_MISMATCH)`
      (design §5.4 rejects "an address outside the signed mesh assignment").
   7. All predicates hold → `Handoff { endpoint, mode }`.

No reason codes were appended: every arm reuses the closed phase-1 §11
vocabulary.

## 3. FLAGGED owner sub-decisions (STOP-AND-FLAG per directive)

### 3.1 RustyDNS mesh-IP signed carriage — **GATED (not defined)**
No signed wire-format object in the repository today carries the RustyDNS
mesh address: design §5.3's `ServiceCapabilityV1.mesh_address` and §5.5's
`ManagedDnsAssignmentV1` are design-only, and the client-facing mesh resolver
today is Rustynet's own loopback resolver (`127.0.0.1:53535`; Windows pins
`:53`). Adding a new signed wire-format field is an owner/security-gated
decision of the same class as the blind-relay §16 gate and the phase-1
prepare-intent wire-format gate (phase-1 notes §3.2). Accordingly the
decision function consumes the endpoint as the abstract `ManagedDnsEndpoint`
input and validates it against the caller-supplied signed mesh range; the
signed carriage decision does not block this control-plane wiring. When the
owner defines the carriage, `ManagedDnsEndpoint` is the type the decoder
constructs; the containment validation moves with it.

### 3.2 Endpoint-absent containment code
`endpoint = None` (RustyDNS endpoint unknown) contains as
`RUSTYDNS_UNREACHABLE`; a present-but-unprovable/out-of-range endpoint
contains as `ASSIGNMENT_MISMATCH`. A single dedicated code for "endpoint not
carried in accepted signed state" would require appending to the closed §11
vocabulary (owner decision); semantics are unchanged either way.

### 3.3 Unlisted-NodeIds client is `NoHandoff`, not `Contained`
A client not selected by an explicit NodeId scope gets its ordinary
non-tandem posture. This mirrors signed-OFF semantics for that client and is
not a containment event. The design is explicit that containment applies to
*selected* DNS (§5.1); scoping an assignment decision per client is the
phase-2 wiring choice recorded here.

### 3.4 Readiness-before-selector evaluation order
When both readiness and selection would fail, the decision surfaces the
readiness reason. The design fixes containment semantics but not the
multi-failure reason precedence; determinism is what matters and the chosen
order (readiness → selection → endpoint) is pinned by tests.

### 3.5 Mesh-prefix supply contract
`MeshIpv4Prefix` is caller-supplied signed network configuration. The domain
layer cannot derive it (transport-agnostic; the mesh range is signed state
reduced elsewhere). A reducer that cannot supply it fails closed
(`ASSIGNMENT_MISMATCH`) rather than skipping containment.

## 4. Verification

- `cargo test -p rustynet-control --lib --all-features`: **542 passed** (23
  new `managed_dns_handoff` tests; every fail-closed arm has a negative test:
  unready/unauthenticated/stale/incompatible readiness, unknown endpoint,
  missing prefix, out-of-range loopback/LAN endpoint, missing scope, blank
  NodeId, unproven exit assignment for both scope kinds, prepare-only and
  draining non-handoff, runtime-contained reason passthrough, readiness
  precedence, prefix construction/containment boundaries).
- `cargo fmt --all -- --check`: clean.
- `cargo check --workspace --all-targets --all-features`: clean.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D
  warnings`: clean.
- `cargo audit --deny warnings`: exit 0. `cargo deny check bans licenses
  sources advisories`: exit 0.

## 5. Not claimed here

Exit-side UDP/TCP port-53 NAT redirect (D-6c), per-OS dataplane enforcement,
RustyDNS process management/startup, the real §6.2 compound readiness probe
(phase-1 `RustydnsReadinessProvider` remains the abstract seam), the signed
`ServiceCapabilityV1`/`TandemDnsPolicyV1`/`ManagedDnsAssignmentV1` wire
formats, cross-repo RustyDNS calls, and any live-lab evidence.

## D-6c delivered — 2026-08-29 (exit :53 transparent NAT redirect: control plane + Linux nft render)

Implemented (control plane + Linux render only; no installer wiring, no live dataplane mutation):

- **Decision fn** `rustynet-control::tandem_dns_redirect::tandem_dns_redirect_decision` — pure, total, fail-closed. `Active(ManagedRedirect)` + ready + scope + on-mesh endpoint + `ProvenSameExit` ⇒ `Redirect{ManagedRedirect, scope, service_address}`; `Off`/`PreparingContained`/`Prepared`/`Draining`/`Active(Managed)` ⇒ `NoRedirect{reason: Option<TandemReasonCode>}` (benign absence `None`, `ResidueError` ⇒ `Some(Residue)`); `RuntimeContained` or any readiness/scope/endpoint/prefix failure ⇒ `ContainNoRedirect{reason}` — **contained posture generates no redirect and the base DNS-fail-closed layer keeps blocking, so no plaintext escape**. No new reason codes (24-variant closed vocabulary unchanged).
- **Linux nft render** `rustynetd::linux_tandem_dns_redirect` — validate-then-format (`render refused` errors): `ip rustynet_tdns_nat4_g<N>` prerouting dstnat DNAT `dport 53 udp/tcp → <svc>:53` (`daddr != svc`, tunnel-iface + selected-source scoped; `AllClientsUsingExit` ⇒ iface-scoped, `NodeIds` ⇒ explicit validated set) + `inet rustynet_tdns_filter_g<N>` forward containment (accept post-DNAT to svc:53, drop selected-source port-53 not translated). **Exact teardown** = `delete table ip rustynet_tdns_nat4_g<N>` + `delete table inet rustynet_tdns_filter_g<N>` only — residue-free (§10.7). Tables additive to / disjoint from base `rustynet_nat_g<N>` exit NAT and killswitch tables.
- **Privileged-helper allowlist** extended with `rustynet_tdns_` prefix (`is_owned_tandem_dns_table_token`, folded into `is_owned_nft_table_token`, negative pins kept) — **security-sensitive widen of the argv-only helper's table ownership tokens**.

Flagged (owner decisions, not shipped here):

- **macOS pf** (§9.2): needs a new reviewed pf `rdr` spec kind in `MacosPfLoadSpec` (today only `nat` kind) + anchor ordering — dataplane flagged, not implemented.
- **Windows WFP** (§9.3): redirect unproven; `PlatformRedirectUnsupported` pre-mutation refusal required — flagged, not implemented.
- **DoT/:853 + DoH-endpoint blocking**: stays OFF per §5.4 defaults; blocklist carries false-positive risk (blocking legit DoH). Owner options: off by default / configurable allowlist-backed blocklist. D-6c ships only the plain :53 redirect.
- **Mesh-IP signed carriage**: still owner-gated (carried from D-6b).

Evidence: control 556+ tests green (14 new decision tests), rustynetd 8 new render tests + helper allowlist pins green; fmt / clippy (`--workspace --all-targets --all-features --locked -D warnings`) / `cargo audit --deny warnings` / `cargo deny check` pass. One pre-existing environment-dependent phase10 macOS test (`macos_assert_dns_protection_requires_active_dns_rules`, host `networksetup` dependency) fails identically on clean HEAD — not this change.

Still open beyond D-6c: rule **installer** wiring (apply/roll-back lifecycle against the privileged path, §9.1 one-transaction readiness flip), per-OS dataplanes above, RustyDNS process management/startup, the real §6.2 compound readiness probe, the signed wire formats, cross-repo RustyDNS calls, and live-lab evidence.

## D-6c-macOS delivered — 2026-08-29 (exit :53 transparent redirect: macOS pf dataplane)

Implemented (pf render + load-spec kind + `MacosCommandSystem` activation/teardown; no daemon installer wiring, no live-lab run):

- **pf render** `rustynetd::macos_tandem_dns_redirect` — pure validate-then-format mirroring the Linux module (`render refused` errors; iface ≤31 `[A-Za-z0-9._-]`, non-zero generation, service-in-mesh fail-closed, `NodeIds` non-empty validated IPv4 order-preserved). Renders the six reviewed rules for the generation-scoped anchor `com.rustynet/tdns_g<N>`: `rdr on <tunnel> inet proto {udp,tcp} from any|{sources} to ! <svc> port 53 -> <svc> port 53` (`!` address negation mirrors the Linux `daddr != svc` loop guard), then containment filter `pass in quick on <tunnel> ... to <svc> port 53 keep state` + `block drop in quick on <tunnel> ... to any port 53 label "rustynet-tdns-contain-{udp,tcp}"`. Terminal `block drop out quick all` stays in the killswitch anchor; the tandem anchor never relaxes base posture. Teardown args = `pfctl -a com.rustynet/tdns_g<N> -F all` only — no base anchor (`com.rustynet/nat`, `com.apple/rustynet_g*`, `blind_exit`) is ever referenced (§10.7 residue-free).
- **Decision reuse** `MacosTandemDnsRedirectPfConfig::from_redirect_decision` accepts ONLY `TandemDnsRedirectDecision::Redirect`; `NoRedirect`/`ContainNoRedirect` refuse — contained/off phases can never install a rule.
- **Load-spec kind** `MacosPfLoadSpec::TandemDnsRedirect` — encode/decode round-trips `kind=tandem_dns_redirect` + `tunnel/generation/svc/mesh_cidr` + optional `source` list (absent ⇒ all-clients; cap `MAX_TANDEM_SOURCES=256`); helper re-derives the anchor from the generation (never trusts the daemon); render invariant arm enforces rdr-only + containment-filter-only (no `nat `, ≥1 rdr); cross-kind tokens rejected on all four kinds. The `macos-pf-load` helper validates/renders through the same path with no argv-schema change.
- **Verification evaluators** `evaluate_macos_tandem_dns_redirect_{translation,filter}` — exact-set match of `pfctl -a <anchor> -s nat` / `-s rules` output against the reviewed forms (pfctl normalization folds: `port = 53`, `!= addr`); reject empty, unreviewed, foreign, or route-to/reply-to/dup-to lines, and missing expected rules.
- **`MacosCommandSystem` wiring** — `pub activate_tandem_dns_redirect(decision, mesh_prefix)` fails closed in order: blind-exit-active refusal → **base DNS fail-closed posture (`dns_protected`) must already be live** (the redirect adds translation on top of containment, never replaces it) → decision must be `Redirect` → load via the privileged builtin → verify BOTH anchors halves live; on drift, teardown + error, leaving only the base posture. `teardown_tandem_dns_redirect` flushes by reference, verifies the anchor is actually empty before clearing the handle (retryable, residue-free). §10.7 ordering: tandem teardown runs BEFORE exit-NAT teardown in `rollback_nat_forwarding` and in the demotion branch of `apply_nat_forwarding`; `reconcile_exit_nat_residue` (non-exit path) sweeps any `com.rustynet/tdns_g*` anchors lost to a crash (`list_tandem_owned_anchors`), since the killswitch sweep only covers `com.apple/rustynet_g*`.
- Tests: 28 new (render determinism/scoping/loop-guard/validation refusals, decision-bridge refusals, teardown disjointness, evaluator tamper/missing/empty rejections, spec round-trips both scopes, cross-kind rejections, invariant regressions, activation ordering pins — the ordering tests return before any pf execution, so they never invoke `pfctl`).

Evidence: `cargo fmt --all -- --check` clean; `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` clean; `cargo check`/`cargo test` for rustynetd (2296 pass) and rustynet-control green; `cargo audit --deny warnings` exit 0; `cargo deny check bans licenses sources advisories` clean. Same pre-existing host-environment failure as the D-6c Linux entry above (`macos_assert_dns_protection_requires_active_dns_rules`, untouched by this diff, fails identically on clean HEAD).

Still flagged after D-6c-macOS:

- **Windows WFP** (§9.3): third per-OS redirect impl, unproven; requires the `PlatformRedirectUnsupported` pre-mutation refusal. NOT STARTED — flagged.
- **DoT/:853 + DoH-endpoint blocking**: owner-gated, OFF by default (false-positive risk); this change redirects plain :53 only.
- **Mesh-IP signed carriage**: owner-gated (carried from D-6b).
- **Daemon installer wiring**: the tandem reconcile loop calling `activate_tandem_dns_redirect`/`teardown_tandem_dns_redirect` (mirrors the Linux gap).
- **Live-proof conditions** (§9.2): root-anchor reachability for `com.rustynet/tdns_g<N>`, `pfctl -s` tuple exposure, and a live-lab run remain unproven — no lab evidence claimed here.

## D-6c-egress delivered — 2026-08-29 (owner decision 3: DoT + known-DoH block, DEFAULT-ON, Linux nft + macOS pf parity)

Implemented (control plane + both OS dataplane renderers; no installer wiring change, no live-lab run):

- **Control plane** `rustynet-control::tandem_dns_redirect` — the `Redirect` arm now carries
  `egress_block: TandemDnsEgressBlockPolicy` (owner decision 3, digest entry 27: DEFAULT-ON
  whenever the redirect is active, NOT opt-in — a false positive fails closed/breaks visibly,
  a false negative fails open/silent leak). The policy is the single canonical value
  `always_on()`: `block_dot = true` (drop outbound tcp+udp `:853` for the selected sources
  except the sanctioned tunnel path to the mesh resolver) plus the pinned known-DoH set on
  `:443`. `NoRedirect`/`ContainNoRedirect` carry nothing — the DoT/DoH layer never installs
  when contained/off; the base DNS-fail-closed posture remains the only DNS behavior.
- **Named, versioned DoH set** — `KNOWN_DOH_RESOLVER_IPS` (const, pinned by test, version
  `KNOWN_DOH_RESOLVER_IPS_VERSION = "2026-08-29.1"`): Cloudflare 1.1.1.1/1.0.0.1, Google
  8.8.8.8/8.8.4.4, Quad9 9.9.9.9/149.112.112.112, Cisco OpenDNS 208.67.222.222/208.67.220.220.
  IPs, not SNI.
- **Linux nft** `rustynetd::linux_tandem_dns_redirect` — the DoT drops (`ip daddr != <svc>`
  udp/tcp `dport 853 drop`) and the DoH drops (each pinned IP, tcp AND udp — the latter covers
  HTTP/3 DoH — `dport 443 drop`) render into the SAME `inet rustynet_tdns_filter_g<N>` forward
  containment chain as the :53 drops. Teardown is unchanged (deletes the two tandem-owned
  tables), so the DoT/DoH drops are removed TOGETHER with the redirect — no separate residue (§10.7).
- **macOS pf** `rustynetd::macos_tandem_dns_redirect` — the pf equivalents (`block drop in quick
  on <tunnel> ... to ! <svc> port 853 label "rustynet-tdns-dot-{proto}"` and
  `block drop in quick on <tunnel> ... to <ip> port 443 label "rustynet-tdns-doh-{proto}"`)
  render into the SAME generation-scoped `com.rustynet/tdns_g<N>` anchor; teardown stays the
  single anchor flush (`pfctl -a com.rustynet/tdns_g<N> -F all`). The filter evaluator's
  expected exact set now includes all 22 pass/block forms (rdr set unchanged). The load-spec
  invariant arm (rdr-only + containment-filter-only) accepts the new forms as-is; encode/decode
  carries no new fields because the policy is inherent to the decision, so helper-side
  re-rendering is byte-identical to daemon-side rendering.
- **Fail-closed bridge** — `MacosTandemDnsRedirectPfConfig::from_redirect_decision` refuses any
  `Redirect` whose `egress_block` is not exactly `always_on()` ("non-canonical DoT/DoH
  egress-block policy"): the renderers always install the full layer, so a non-canonical policy
  would be a silent gap — refused, never partially rendered.
- **HONEST RESIDUAL (documented, not an open door)** — DoH-over-`:443` to an ARBITRARY host is
  technically indistinguishable from HTTPS without SNI inspection, so "block all DoH" is
  unachievable by any IP-list mechanism. The pinned set blocks the well-known public resolvers
  (the 95% case); arbitrary self-hosted DoH is a KNOWN MECHANISM LIMIT with a named future work
  item: **SNI-inspection egress filtering** (follow-up, not in scope here).
- Tests: control plane +5 (canonical policy on active redirect, pinned-set pin, exhaustive
  non-redirect arms carry nothing, reconcile agreement), rustynetd +6 (Linux DoT/DoH render in
  the generation-scoped table + scoped-count + teardown-together; macOS anchor render + bridge
  non-canonical refusals), plus updated count pins (pf ruleset 24 lines; NodeIds fragment on all
  24 rules).

Evidence: `cargo test -p rustynet-control --lib --all-features` 573 pass; `cargo test
-p rustynetd --lib --all-features` 2309 pass; `cargo fmt --all -- --check` clean; `cargo clippy
--workspace --all-targets --all-features --locked -- -D warnings` clean; `secrets_hygiene_gates.sh`
PASS (18 checks). No lab run (per scope).

Still open beyond D-6c-egress: Windows WFP dataplane (§9.3, unproven), daemon installer wiring
(reconcile loop calling activate/teardown), RustyDNS process management, real §6.2 compound
readiness probe, signed wire formats, live-lab evidence, and the SNI-inspection follow-up named above.
