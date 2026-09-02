# Service-Hosting Roles — Phase 2 Design (service-access-policy enforcement + gateway/service integration)

**Date:** 2026-08-29 · **Status:** design, doc-only (no code in this change) · **Owner:** service-hosting roles program
**Builds on:** [`ServiceHostingRolesRoadmap_2026-06-11.md`](./ServiceHostingRolesRoadmap_2026-06-11.md) (M2–M3), [`ServiceHostingRolesDeltaPlan_2026-06-11.md`](./ServiceHostingRolesDeltaPlan_2026-06-11.md) (D13.c/d landed), roadmap §7.1 (phase-1 verification note, 2026-08-29).
**Precedence:** `documents/Requirements.md` → `documents/SecurityMinimumBar.md` §6.E (E1–E4) → this document.

Phase 1 landed the control-plane scaffolding and proved it in-tree (roadmap §7.1). Phase 2 is the
**runtime wiring**: make the daemon actually drive the enforcement scaffolding it already has, so
`nas` and `llm` nodes serve only peers that the signed state authorises — per session, per frame,
per token event — with session severance on revocation, and then prove it live (roadmap M5 rows).

This document is deliberately explicit about what **exists** vs what is **needed**, so a follow-up
code job can implement Phase-2 M2 directly from §4 without re-deriving the map.

---

## 1) Grounded inventory — exists vs needed

Everything below was re-verified in-tree at the commit this document lands on. Line numbers are
indicative (they drift); the symbol names are the stable reference.

### Exists (no new type, no new crypto, no new wire format)

| Primitive | Where | Notes |
|---|---|---|
| Service capabilities in signed membership | `crates/rustynet-control/src/role_presets.rs` — `Capability::ServesNas`/`ServesLlm` (serde `serves_nas`/`serves_llm`) | Signed metadata; tamper test `tampered_service_hosting_capability_invalidates_signature` (`membership.rs` L3419) proves fail-closed at signature verification. |
| Capability-level co-location validation | `crates/rustynet-control/src/membership.rs` ~L2726 | blind_exit × service-hosting refused ("strictest default"); blind_relay requires exactly `{relay_host, blind_relay}` and refuses `serves_*`. |
| Service view from signed membership | `crates/rustynetd/src/service_exposure.rs` — `service_hosting_view_from_membership` | Absent/inactive node serves nothing (test L756). Tunnel-only bind: `validate_tunnel_only_bind` (tests L657–710). |
| Tunnel→identity resolution | `crates/rustynetd/src/service_exposure.rs` L225/234 — `VerifiedPeerIdentity { node_id, overlay_addr }` + `resolve_peer_identity(source, overlay_addr_to_node)` | Map is built by the daemon from signed state only; **unknown source ⇒ `UnknownPeerAddress` fail-closed**. |
| Policy engine with service contexts | `crates/rustynet-policy` — `ContextualPolicySet::evaluate_with_membership`, `TrafficContext::{NasService,LlmService}` | Engine default is `Decision::Deny`; rules with an empty `contexts` list never match service contexts (context hardening landed in D13.b). |
| LLM scopes | `crates/rustynet-policy/src/lib.rs` — `LlmAccessScope`, `LlmScopePolicy` | Scopes only ever *narrow* an existing Allow; they are never an authorisation source. **Deny-on-absent (OG-1 resolved, Option B):** no scope entry ⇒ every model denied; `unrestricted` marker = full access. |
| E2 access evaluation | `crates/rustynetd/src/service_exposure.rs` L257 — `evaluate_service_access(policy, membership, …)` | One enforcement point for every new session; empty/missing policy ⇒ deny. |
| Materialised access state | `crates/rustynetd/src/service_access_state.rs` — `grants.v1` (L43, one authorised peer node-id per line), `peers.v1` (L44), `scopes.v1` (L45); `derive_service_access_snapshot`, `write_service_access_state`, `refresh_grants_and_scopes`, removal + `force_deny_all` (L208) | Written **from** verified signed state at the four signed-state commit points (`daemon.rs` `materialize_service_access_state` L5327 → L5795/L8635/L9696/L10355). Write failure degrades to deny-all; removal tears `grants.v1` first (teardown-before-revoke). The files are **materialised artifacts, not signed documents** — their authority is the signed snapshot they were rendered from. |
| Sibling-binary per-frame re-check | `crates/rustynet-nas/src/main.rs` ~L269/299 | No/empty access files ⇒ deny-all; grants re-read per frame so revocation lands mid-session. Same pattern in `crates/rustynet-llm-gateway` per frame **and** per token event. |
| Lifecycle controller (scaffolding) | `crates/rustynetd/src/service_exposure.rs` — `ServiceExposureController` | Deploy-before-advertise, fail-closed health gate, `admit_session`, session severance on policy change, teardown-before-capability-release (`capability_release_ready`). **Unit-tested only — NOT yet driven by the daemon runtime. This is the phase-2 gap.** |
| Gate scripts | `scripts/ci/nas_default_deny_gates.sh`, `llm_default_deny_gates.sh`, `llm_exit_coexistence_gates.sh` | Existing per-milestone gates to extend, not replace. |

### Needed (phase-2 work — all composition/wiring, no new primitives)

1. **Daemon runtime driving `ServiceExposureController`** — the daemon never instantiates it in a
   production path today. Needed: one owner inside `rustynetd` that starts/stops the sibling
   binaries when `serves_nas`/`serves_llm` appear/disappear in verified signed state, and consults
   `admit_session` before proxying a connection to the sibling.
2. **Identity handoff at connection time** — the daemon must resolve the connection's tunnel source
   via `resolve_peer_identity` and pass the resulting `VerifiedPeerIdentity` to the sibling (and
   refuse to proxy when resolution fails). The sibling-side *consumption* of this identity exists in
   design; the daemon-side production handoff does not.
3. **Session severance wiring on policy change** — controller supports it; the daemon must react to
   a signed-state commit that removes a peer's grant by closing that peer's live sessions (E3), not
   just rewriting `grants.v1`.
4. **Live-lab evidence rows (roadmap M5)** — nas: deploy→advertise→authorise→backup→restore→
   revoke(severance)→undeploy; llm: deploy→advertise→authorise→stream (no API key)→
   exit-coexistence→revoke→undeploy.

### Explicitly NOT needed

- **No new crypto.** Signing stays `rustynet-crypto` (existing membership-bundle signature path).
- **No new wire-format field** for phase 2 enforcement itself: the signed membership bundle already
  carries capabilities + policy (`ContextualPolicySet`) and the access files are derived, not
  distributed. Any *new* signed field (e.g. per-service scope table shipped inside the bundle — §5
  OG-3) is wire-format-gated and owner-decided, not assumed here.
- **No new policy type.** `ContextualPolicySet` + `TrafficContext::{NasService,LlmService}` +
  `LlmAccessScope`/`LlmScopePolicy` already express the signed policy. A separate `nas` scope type
  is an owner decision (§5 OG-2), not a phase-2 requirement.

---

## 2) Service-access-policy enforcement (design)

### Policy shape — exists, composed from signed primitives

The signed policy is the existing membership-bundle policy (`ContextualPolicySet`) evaluated with
`TrafficContext::NasService` / `TrafficContext::LlmService`. Authorisation = a signed rule whose
contexts explicitly name the service context and whose action is Allow **for the caller's node
selector**; scopes (`LlmScopePolicy`) may then narrow it. Nothing else authorises — this is the
default-deny posture required by `SecurityMinimumBar.md` §6.E (E2) and already enforced by the
engine's `Decision::Deny` default plus the empty-contexts rule hardening.

### Enforcement points — three layers, fail-closed each

1. **Session admission (E2, primary):** daemon-side `evaluate_service_access` (one call site per
   accepted tunnel connection, inside the phase-2 controller drive) — caller's `VerifiedPeerIdentity`
   + current signed policy. Deny ⇒ connection never reaches the sibling.
2. **Sibling-side per-frame re-check (defence in depth):** each `nas`/`llm-gateway` daemon re-reads
   the materialised `grants.v1` per frame (llm additionally per token event) against the identity the
   daemon handed it. Absent/empty/unreadable file ⇒ deny-all (already implemented and tested).
   Rationale: revocation must land even if the proxy layer is bypassed or a commit is in flight.
3. **Materialisation correctness:** `materialize_service_access_state` at the four signed-state
   commit points; write failure ⇒ `force_deny_all` (deny-all, never stale grants); capability
   removal tears `grants.v1` first.

**Fail-closed default:** no policy entry ⇒ deny; missing identity mapping ⇒ deny; unreadable access
state ⇒ deny-all; controller health gate failing ⇒ service not advertised (deploy-before-advertise).

### Distribution — existing channels only

Signed membership bundle (capabilities + policy + scopes) → verified by the daemon → materialised
to `grants.v1`/`peers.v1`/`scopes.v1` → re-read by the siblings. No new distribution path, no new
signed document, therefore **no wire-format gate** for the phase-2 core. (Owner-gated exception:
§5 OG-3.)

---

## 3) Identity-from-tunnel (design)

Both siblings are **tunnel-shaped binds only** (`validate_tunnel_only_bind`, E1): the only way in is
through the mesh interface, so the connection's source address is a mesh overlay address.

Chain, per connection:

```
tunnel source IP → resolve_peer_identity (signed-state-built map; unknown ⇒ deny)
                → VerifiedPeerIdentity { node_id, overlay_addr }
                → evaluate_service_access(policy, membership, identity)   [E2, daemon]
                → handoff to sibling: identity is the ONLY identity source
                → sibling re-checks grants.v1 per frame (nas) / per frame+token event (llm)
                → nas: serve caller's own namespace (per-peer dirs, AAD-bound AEAD)
                → llm: proxy to loopback-only inference engine (no API key needed)
```

Hard rules (all already exist as code or design text; phase 2 wires the daemon half):

- The sibling **must ignore any client-supplied identity material** — `VerifiedPeerIdentity`
  doc text (service_exposure.rs L219–223) already mandates this; the phase-2 handoff protocol must
  make it structurally true (identity arrives daemon-side, never in the client-visible stream).
- Unmapped tunnel source ⇒ deny (fail-closed), never "treat as anonymous with limited access".
- No grant ⇒ deny before any bytes are proxied; a revoked grant ⇒ in-flight session severed (E3).
- The loopback engine boundary (`InferenceEngine`, loopback-only check) is unchanged by phase 2.

---

## 4) Per-milestone task breakdown (buildable)

Each task lists: enforcement point (file where the change lands), acceptance criteria (fail-closed),
verification. Naming: `P2-M2` = roadmap M2 (nas) completion scope, `P2-M3` = roadmap M3 (llm).
Shared foundation task `P2-M1` must land first; both milestones depend on it.

### P2-M1 (shared foundation) — daemon drives the controller

1. **Controller ownership in `rustynetd`.** One module owns a `ServiceExposureController` instance;
   starts the `rustynet-nas`/`rustynet-llm-gateway` sibling binary when verified signed state
   carries `serves_nas`/`serves_llm`, stops it (teardown-before-capability-release) when the
   capability disappears.
   - Enforcement point: `crates/rustynetd/src/daemon.rs` (new controller-drive module; hook the four
     existing signed-state commit points that already call `materialize_service_access_state`).
   - Acceptance: absent capability ⇒ sibling process not running and access dirs cleared (already
     enforced by materialisation); present capability + failed health probe ⇒ **not advertised**
     (deploy-before-advertise, fail-closed); advertise happens only after health gate passes.
   - Verification: unit tests driving the controller against a stub sibling (deterministic, no
     real binary needed for the state machine); extend `scripts/ci/nas_default_deny_gates.sh` with a
     "capability absent ⇒ nothing listening" case.
2. **Session admission wiring.** Every accepted tunnel connection to a service port resolves
   identity then evaluates access before proxying.
   - Enforcement point: the controller-drive module calling `resolve_peer_identity` +
     `evaluate_service_access` (single call site — keep it one hardened path).
   - Acceptance: unmapped source ⇒ connection refused, sibling never sees it; deny decision ⇒ same;
     only Allow proxies through, with `VerifiedPeerIdentity` attached.
   - Verification: negative tests (unknown source, deny rule, empty policy) at the unit level +
     a `traffic`-style live stage in M5.

### P2-M2 (roadmap M2 completion) — nas enforcement live

1. **Identity handoff to `rustynet-nas`.** Daemon passes `VerifiedPeerIdentity` per accepted
   session; the sibling treats it as the only identity source (client-supplied identity is
   structurally unreachable — it is not part of the framed protocol the client speaks).
   - Enforcement point: controller-drive module (daemon side) + consumption in
     `crates/rustynet-nas/src/main.rs` session setup.
   - Acceptance: every store operation resolves to the handed identity's per-peer namespace; no
     code path accepts a peer id from the wire for authorisation purposes (peer id on the wire may
     only *confirm*, never *establish*, identity — mismatch ⇒ deny + audit event).
   - Verification: unit test "wire-supplied peer id ≠ tunnel identity ⇒ deny"; existing
     per-frame deny-all tests still green.
2. **Grant lifecycle e2e (offline-testable).** Authorise → serve → revoke ⇒ mid-session denial.
   - Acceptance: revocation (signed state commit) rewrites `grants.v1` and the sibling's per-frame
     re-read denies the next frame of the previously-authorised session; write failure ⇒ deny-all.
   - Verification: existing `service_access_state.rs` tests cover the file semantics; add one
     integration test: session open → revoke → next frame denied (asserts the daemon + sibling
     wiring, not just the files).
3. **Gate.** `scripts/ci/nas_default_deny_gates.sh` extended with the admission-wiring cases above;
   must pass before M5 nas rows are attempted.

### P2-M3 (roadmap M3 completion) — llm gateway enforcement live

1. **Identity handoff + per-token-event enforcement.** Same handoff as P2-M2; llm additionally
   re-checks the grant per token event (already implemented in the crate) and applies
   `LlmScopePolicy` narrowing (models/tokens/rate) — scope resolution uses the caller-ordered
   selector convention (POL-12, `LlmScopePolicy::scope_for`).
   - Enforcement point: controller-drive module + `crates/rustynet-llm-gateway` session/token path.
   - Acceptance: stream to a non-granted peer ⇒ nothing (deny before first token); mid-stream
     revocation ⇒ stream severed; scope with `allowed_models: Some([])` ⇒ every model denied even
     though the grant stands (scope narrows, grant authorises); no scope entry ⇒ deny every model
     (OG-1 resolved as Option B: deny-on-absent, explicit `unrestricted` marker = full access).
   - Verification: unit tests for mid-stream severance + scope narrowing; extend
     `scripts/ci/llm_default_deny_gates.sh`.
2. **Exit coexistence under live controller.** LLM service traffic stays intra-mesh while client
   egress uses the exit node — the overlay-exception guard (`enforce_overlay_exception_for_exit_routes`)
   must hold with the controller-driven advertise path active.
   - Acceptance: existing coexistence invariant preserved; advertise/undeploy cycles do not leak
     service routes into the exit path.
   - Verification: `scripts/ci/llm_exit_coexistence_gates.sh` (existing) + M5 live stage.
3. **Gate.** Both llm gate scripts green before M5 llm rows.

### M5 (both milestones converge) — live-lab evidence

Run the delta-plan stage scripts (nas: deploy→advertise→authorise→backup→restore→revoke-severance→
undeploy; llm: deploy→advertise→authorise→stream-no-key→exit-coexistence→revoke→undeploy) through
the `--node` orchestrator; append + verify rows in
`documents/operations/live_lab_node_run_matrix.csv` (AGENTS.md §2/§10.9: row existence ≠ proof —
take pass/fail from the stage's own report artifact). Linux first (parity mandate: mac/win nas/llm
cells are separately gated and remain ⛔ until live evidence).

---

## 5) OWNER-GATED decisions (flagged, NOT decided here)

These require an owner decision before or during implementation. Defaults named are the
**conservative reading of current code/docs**, recorded so the implementer does not silently choose.

- **OG-1 — Policy default posture for "grant without scope".** Today a peer with a valid Allow but
  no `LlmScopePolicy` entry gets the **full grant** (`scope_for` returning `None` leaves the grant
  unrestricted; documented fail-open-by-design at `rustynet-policy/src/lib.rs` L344–349 — the grant
  is the authorisation, the scope is an optional restriction). Alternative posture: absent scope ⇒
  minimal default scope (e.g. no models). **Owner must confirm** the current posture or mandate the
  stricter one. Note the asymmetry risk: `allowed_models: Some([])` denies all models while `None`
  allows all — an admin UI must never render the empty-list case as "none configured".
- **OG-2 — Shared vs separate scope type for nas.** `LlmAccessScope`/`LlmScopePolicy` are llm-only;
  nas currently has scopes.v1 materialisation but no distinct scope semantics in `rustynet-policy`.
  Options: (a) nas scopes stay absent (grant = full per-peer namespace — current de-facto posture),
  (b) add `NasAccessScope` (e.g. quota ceilings, snapshot-count limits) mirroring the llm pattern.
  **Owner decides scope;** if (b), it is a new type composed from existing primitives (no new
  crypto), and `scopes.v1` rendering in `service_access_state.rs` needs the matching case.
- **OG-3 — Any new signed wire-format field.** Current design needs none (§1). If the owner elects
  to distribute per-service scopes inside the signed bundle as a first-class signed field (instead
  of the current bundle-policy + materialisation path), that is a **wire-format change**: it is
  gated on the wire-format governance process and must be versioned with replay/rollback protection.
  Flagged only — not designed, not assumed.

---

## 6) Cross-references

- Roadmap: [`ServiceHostingRolesRoadmap_2026-06-11.md`](./ServiceHostingRolesRoadmap_2026-06-11.md) §3 (M2/M3), §7 (tracker), §7.1 (phase-1 evidence)
- Delta plan: [`ServiceHostingRolesDeltaPlan_2026-06-11.md`](./ServiceHostingRolesDeltaPlan_2026-06-11.md) §3 D13.c/d, §2 defect lessons
- Security bar: `documents/SecurityMinimumBar.md` §6.E (E1–E4 enforcement-point map)
- Role designs: [`NasNodeRoleDesign_2026-06-11.md`](./NasNodeRoleDesign_2026-06-11.md), [`LlmNodeRoleDesign_2026-06-11.md`](./LlmNodeRoleDesign_2026-06-11.md)
