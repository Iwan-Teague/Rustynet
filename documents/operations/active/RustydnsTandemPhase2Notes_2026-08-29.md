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
