# Rustynet Node Role Taxonomy Extension — Service-Hosting Roles (`nas`, `llm`)

- Date: 2026-06-11
- Status: active (design source-of-truth for the two new service-hosting node-role presets)
- Owner: Rustynet
- Parent doc: [`NodeRoleTaxonomy_2026-05-21.md`](./NodeRoleTaxonomy_2026-05-21.md) — that document cements the existing six user-selectable presets (`relay`, `anchor`, `exit`, `blind_exit`, `client`, `admin`). This document **extends** that taxonomy with two new presets, `nas` and `llm`, taking the surface to **eight roles**. It does not supersede the parent; it adds to it. Where the parent doc and this document overlap (transition matrix, CLI surface, wizard, gates), this document gives the **delta** and defers the mechanics to the parent.
- Child docs (deep dives): [`NasNodeRoleDesign_2026-06-11.md`](./NasNodeRoleDesign_2026-06-11.md), [`LlmNodeRoleDesign_2026-06-11.md`](./LlmNodeRoleDesign_2026-06-11.md).

---

## 0) Purpose of this document

The user wants two new always-on home devices to be first-class roles in the mesh:

- a **NAS node** — a dedicated network-attached-storage box that other devices back up media and files to. The user-facing consumer app (a future **RustyBackup** client) talks to it.
- an **LLM node** — a dedicated AI-hosting box that exposes an inference API. A future **RustyAI** client (a Claude-Code / ChatGPT / Codex-style text UI that can chat, upload files, and edit projects on the connecting machine) consumes that API.

Both are fundamentally a **new category** of role that the existing taxonomy does not yet have. The six existing roles are all about *network plumbing* — they move, forward, gate, or egress mesh traffic (`relay`, `exit`, `anchor`) or they define a local control posture (`admin`, `client`, `blind_exit`). Neither hosts an **application-layer service** that other peers consume *as a service*.

`nas` and `llm` are the first two **service-hosting roles**: a `rustynetd` peer that runs a co-deployed application server and exposes it **only over the mesh tunnel**, governed by **default-deny** signed policy. This document defines that category once, so that future service-hosting roles (media server, Git host, etc.) slot into the same frame rather than each reinventing the exposure model.

If a later document or commit conflicts with this design, this document is the source of truth for the `nas` and `llm` roles, and for the service-hosting-role category, until explicitly superseded.

---

## 1) Design constraint check (why this fits Rustynet, not bolted on)

Per [`CLAUDE.md`](../../../CLAUDE.md) §3 and [`get_architecture_constraints`], every addition must respect the non-negotiables. The service-hosting category is designed to satisfy them rather than work around them:

| Constraint | How `nas` / `llm` satisfy it |
|---|---|
| Rust-first | New sibling services (`rustynet-nas`, `rustynet-llm-gateway`) are Rust crates. They wrap, not reimplement, third-party storage/inference engines behind a process boundary (see child docs). |
| No custom crypto, no custom VPN protocol | The service endpoint inherits confidentiality + peer authentication from the **existing WireGuard tunnel**. No new transport crypto. The app server never terminates its own TLS for mesh peers; the tunnel is the secure channel. |
| WireGuard stays an adapter | These roles consume the dataplane through the same backend-agnostic seam as any peer. No service code imports backend/WireGuard types. The "reachable over the tunnel" property is expressed as a policy/route fact, not a WireGuard fact. |
| Default-deny mandatory | A service-hosting node exposes **nothing** until a signed policy explicitly authorises a named peer (or group) to reach the service. Empty/missing/stale policy ⇒ deny, reusing `rustynet-policy`'s existing `Decision::Deny` default (see `PolicySet::evaluate`, `crates/rustynet-policy/src/lib.rs:94`). |
| Fail closed | Missing capability, missing service-access policy, unverified signed state, or a service-process health failure all collapse to "endpoint refuses connections" — never "open to all". |
| One hardened execution path | One way to expose the service (tunnel-bound listener + signed service-access policy). No "LAN convenience" fallback, no unauthenticated localhost bypass for remote peers, no downgrade branch. |
| No TODO deferrals in completed deliverables | The build slices in §7 and the child docs are end-to-end; deferred platform parity (Windows/macOS) is tracked honestly in the platform matrix, not hidden behind placeholders. |

The single most important sentence in this document: **a service-hosting role changes what an authorised peer can reach, never who is trusted.** Trust is still rooted in the offline membership owner and verified independently by every peer. `serves_nas` / `serves_llm` are operational metadata in signed membership, exactly like `serves_exit` / `serves_relay` — they never gate signature verification.

---

## 2) The two new roles (user-facing presets)

Extends [`NodeRoleTaxonomy_2026-05-21.md`](./NodeRoleTaxonomy_2026-05-21.md) §2.

| Role | Plain English | Internal composition |
|---|---|---|
| `nas` | "This is my always-on storage box. Other devices back up media and files to it via RustyBackup. It hosts storage; it does not route mesh traffic." | Primary=Admin, `serves_nas=true`, `rustynet-nas` co-deployed |
| `llm` | "This is my AI box. It runs models and exposes an inference API that RustyAI clients call over the mesh. It hosts inference; it does not route mesh traffic." | Primary=Admin, `serves_llm=true`, `rustynet-llm-gateway` co-deployed |

Each is a **complete composition**, like the existing six. Picking `nas` does not require also picking `anchor`, though the common home deployment co-locates `nas` (or `llm`) on the same physical box as the `anchor`. That composite is reached the same way the parent doc reaches `anchor + exit`: pick the base preset, then `rustynet capability add serves_nas` (operator-mode only; never shown in the wizard). See §6.

**Why these are not just "run an app on a client":** the point of making them roles is that the **exposure, authorisation, service-deploy lifecycle, audit, and platform gating** are all handled by Rustynet's hardened, signed, default-deny machinery — not by the operator hand-rolling a firewall rule and hoping. A NAS you expose by hand is an open SMB share waiting to be ransomwared; a NAS exposed as a Rustynet role is reachable only by signed-authorised mesh peers over an encrypted tunnel, with a fail-closed default.

---

## 3) Internal data model delta (two-axis, unchanged shape)

The two-axis model from the parent doc §3 is unchanged. We add **two Axis-2 capabilities**; we add **zero Axis-1 primaries**.

### 3.1 Axis 1 — Primary role (NOT extended)

`NodeRole` stays `Admin / Client / BlindExit` (`crates/rustynetd/src/daemon.rs:1195`). `nas` and `llm` are **not** new `NodeRole` variants — they are presets that select `NodeRole::Admin` + a capability. This mirrors exactly how `exit`, `relay`, and `anchor` already work and preserves the orthogonality invariant the parent doc and the anchor doc both depend on.

### 3.2 Axis 2 — Mesh capabilities (two new, signed)

Add to the `Capability` enum in `crates/rustynet-control/src/role_presets.rs` and to the parallel `RoleCapability` enum in `crates/rustynet-control/src/roles.rs`:

| Capability | Wire string | What it does |
|---|---|---|
| `Capability::ServesNas` | `serves_nas` | Daemon co-runs `rustynet-nas` and binds its storage/backup API to the **tunnel interface only**. Other peers may reach it **only** if signed service-access policy authorises them. |
| `Capability::ServesLlm` | `serves_llm` | Daemon co-runs `rustynet-llm-gateway` and binds the inference API to the **tunnel interface only**. Same default-deny authorisation. |

Both follow the existing `serves_*` precedent exactly. They are signed into the per-node membership entry (`node_capabilities`), so a node **cannot self-promote** into a service host — the membership owner signs a bundle granting the capability. The daemon reads its own capability set from the signed bundle on bootstrap and reload (parent doc §3.2 "critical invariant").

### 3.3 Preset → composition mapping (extends parent §3.3)

| Preset | Axis 1 | Axis 2 capabilities |
|---|---|---|
| `nas` | `Admin` | `serves_nas` |
| `llm` | `Admin` | `serves_llm` |

These two rows append to `ROLE_PRESET_TABLE` (`crates/rustynet-control/src/role_presets.rs:235`). The table length assertion changes from 6 to 8; the existing `preset_table_has_exactly_six_entries` test is renamed/retargeted to 8, and per-preset composition tests are added (mirroring `relay_composition` / `anchor_composition`).

### 3.4 Service-binary requirement (new predicate, mirrors relay)

The parent doc has `capabilities_require_relay_binary`. Add the symmetric predicates so the transition orchestrator knows which sibling service to deploy/undeploy:

```rust
pub fn capabilities_require_nas_binary(capabilities: &[Capability]) -> bool {
    capabilities.iter().any(|c| matches!(c, Capability::ServesNas))
}
pub fn capabilities_require_llm_binary(capabilities: &[Capability]) -> bool {
    capabilities.iter().any(|c| matches!(c, Capability::ServesLlm))
}
```

`TransitionPlan` gains four flags symmetric to the relay ones: `requires_nas_deploy`, `requires_nas_undeploy`, `requires_llm_deploy`, `requires_llm_undeploy`. (Alternatively, generalise to a `service_deploys: Vec<ServiceKind>` / `service_undeploys: Vec<ServiceKind>` pair — the child docs recommend the generalised form so future service-hosting roles do not keep widening the struct. Either is acceptable; the generalised form is preferred.)

---

## 4) Transition matrix delta (extends parent §5)

The eight-role matrix keeps every rule from the parent doc §5 and adds the two new rows/columns. The new roles behave **exactly like `relay`**: adding the capability is `signed + service-deploy`, removing it is `signed + service-undeploy`, and there is no irreversibility (only `blind_exit` is irreversible).

Cell legend (unchanged): `local` / `signed` / `blocked` / `irrev`; `service-deploy` / `service-undeploy` annotate the sibling-service side-effect.

| From ↓ \ To → | client | admin | exit | blind_exit | relay | anchor | nas | llm |
|---|---|---|---|---|---|---|---|---|
| **client** | — | `local` | `local+signed` | `irrev` | `local+signed+deploy` | `local+signed+deploy` | `local+signed+deploy` | `local+signed+deploy` |
| **admin** | `local` | — | `signed` | `irrev` | `signed+deploy` | `signed+deploy` | `signed+deploy` | `signed+deploy` |
| **exit** | `signed+local` | `signed` | — | `irrev` | `signed+deploy` | `signed+deploy` | `signed+deploy` | `signed+deploy` |
| **blind_exit** | `blocked` | `blocked` | `blocked` | — | `blocked` | `blocked` | `blocked` | `blocked` |
| **relay** | `signed+undeploy+local` | `signed+undeploy` | `signed+undeploy` | `irrev` | — | `signed+deploy` | `signed+deploy+undeploy` | `signed+deploy+undeploy` |
| **anchor** | `signed+undeploy+local` | `signed+undeploy` | `signed+undeploy` | `irrev` | `signed+undeploy` | — | `signed+deploy+undeploy` | `signed+deploy+undeploy` |
| **nas** | `signed+undeploy+local` | `signed+undeploy` | `signed+undeploy` | `irrev` | `signed+deploy+undeploy` | `signed+deploy+undeploy` | — | `signed+deploy+undeploy` |
| **llm** | `signed+undeploy+local` | `signed+undeploy` | `signed+undeploy` | `irrev` | `signed+deploy+undeploy` | `signed+deploy+undeploy` | `signed+deploy+undeploy` | — |

Notes on the new cells:

- **`nas` ↔ `relay` / `anchor`** is `deploy+undeploy` because the sibling service differs: leaving `nas` undeploys `rustynet-nas`, entering `relay` deploys `rustynet-relay`. Each sibling service has its own independent deploy/undeploy lifecycle (the relay predicate, the nas predicate, the llm predicate are independent), so a single transition can both undeploy one and deploy another. This is the same shape as `relay → anchor` already being a no-op only because they share the relay binary; `nas` and `relay` share nothing, hence both side-effects fire.
- **`nas` ↔ `llm`** is `signed+deploy+undeploy`: undeploy `rustynet-nas`, deploy `rustynet-llm-gateway` (you would rarely do this — they are different physical boxes — but the matrix must be total).
- **No new `irrev` or `blocked` cells.** Only `blind_exit` keeps those. A NAS or LLM node is a normal Admin-primary node; downgrading it is always a signed capability revocation, never a factory reset.
- **`*+undeploy`-before-revoke ordering is mandatory** for the service binary, exactly as relay (parent §5 + SecurityMinimumBar §6.D control 5). For service-hosting roles there is an **additional** fail-closed step: the daemon must tear down the tunnel-bound listener and drop all in-flight authorised sessions **before** the capability leaves local state, so a revoked NAS/LLM cannot keep serving an already-connected peer. This is the service-hosting analogue of §6.D control 7 (exit-NAT teardown on revocation).

The `transition_plan` validator in `role_presets.rs` computes all of this from the capability deltas automatically — the matrix above is the **expected-result oracle** for the exhaustive `transition_matrix_matches_taxonomy_doc` test (extend the reference `expected_kind` helper and the `all` array to eight presets).

---

## 5) Secure exposure model (the heart of the category)

This section defines how a service-hosting role exposes its endpoint. The child docs reference it rather than restating it. Six rules, all fail-closed:

1. **Tunnel-bound listener only.** The service API binds to the node's **mesh tunnel address** (the WireGuard interface IP / Rustynet overlay address), never `0.0.0.0`, never the LAN interface, never the public interface. A peer can reach the service only by already being inside the tunnel — which already required signed membership + a verified WireGuard handshake. There is no "expose to LAN" flag; the one hardened path is tunnel-only.

2. **Default-deny per-peer authorisation.** Being inside the tunnel is necessary but **not sufficient**. Which peers may reach a given service-hosting node is governed by signed policy evaluated through `rustynet-policy`. We model service access as a new `TrafficContext` (e.g. `TrafficContext::NasService`, `TrafficContext::LlmService`) so the existing `ContextualPolicySet::evaluate_with_membership` (`crates/rustynet-policy/src/lib.rs:187`) decides access. Empty/missing/malformed policy returns `Decision::Deny` (the engine's existing default — `crates/rustynet-policy/src/lib.rs:144,219`). No policy ⇒ nobody reaches the NAS/LLM, even peers in the same mesh.

3. **Authorisation lives in signed state.** The allow-list of peers/groups permitted to reach a service-hosting node is part of the signed policy/assignment bundle minted by the membership owner — not local config on the service node, and not self-asserted by the connecting peer. A peer presents its node identity (already authenticated by the tunnel); the service node checks the signed policy. This reuses the assignment-bundle authorisation precedent that `serves_exit` already uses ("subject to signed assignment-bundle authorisation", parent §2).

4. **App-layer auth is a second factor, never the first.** The application server (RustyBackup protocol, OpenAI-style LLM API) MAY layer its own token/account auth on top — and the child docs specify a node-issued capability token for this — but that is **defence-in-depth**, never the trust boundary. The trust boundary is tunnel membership + signed policy. The app server must still fail closed if Rustynet has not handed it a verified peer identity. No app-layer token can grant access that signed policy denies.

5. **No custom transport crypto.** The service inherits confidentiality and integrity from the tunnel. The app server does not run its own TLS for mesh peers, does not invent a handshake, does not hold long-lived bearer secrets that bypass the mesh. Any in-process token the node issues to a peer is short-lived, single-audience, and verified with the existing `rustynet-crypto` primitives — no new crypto.

6. **Fail-closed health gating.** If the sibling app process is unhealthy, crashed, or its signed access policy is stale/unverifiable, the daemon stops accepting connections to the service endpoint rather than degrading to an unauthenticated or unmediated mode. Deploy-before-advertise and undeploy-before-revoke (§4) make the capability flag honest: the bundle never advertises `serves_nas`/`serves_llm` for a node that cannot actually serve it safely.

The MagicDNS signed zone ([`MagicDnsSignedZoneSchema_2026-03-09.md`](./MagicDnsSignedZoneSchema_2026-03-09.md)) gives each service-hosting node a stable overlay name (e.g. `vault.nas.<mesh>`, `brain.llm.<mesh>`) so RustyBackup/RustyAI clients target a name, not a raw tunnel IP. The name resolves only inside the mesh.

---

## 6) CLI / wizard / advanced-composite delta

Extends parent §4 and §6. No new verb *shapes* — the existing `role` and `capability` verbs already generalise:

- `rustynet role set nas` / `rustynet role set llm` — same orchestration as `role set relay`: validate transition → deploy sibling service → verify health → emit unsigned `MembershipUpdateRecord` for owner signing.
- `rustynet role list` now prints eight presets.
- `rustynet capability add serves_nas` / `add serves_llm` — operator-mode composite (e.g. an `anchor` box that is *also* the NAS). Never shown in the wizard.
- Wizard (`start.sh` + `rustynet operator menu`): the eight-role list shows `nas` and `llm` only where platform-eligible (§7). Because a typical mesh has at most one of each, the wizard annotates them "(one box per mesh, typically)" like `anchor`, and prompts for service-deploy confirmation (they install a new system service) plus the resource note (LLM wants a GPU/accelerator; NAS wants a data disk).

New IPC commands: none beyond the parent's `RoleSet/RoleStatus/RoleTransitionCheck/CapabilityAdd/Remove/List` — `serves_nas`/`serves_llm` are just new capability strings those verbs accept. All still gated by `NodeRole::Admin`, with `RoleStatus`/`CapabilityList` read-only for `Client`/`BlindExit` (parent §4.3).

---

## 7) Per-platform eligibility delta (extends parent §7 and the platform matrix)

| Role | Linux | macOS | Windows | iOS | Android |
|---|---|---|---|---|---|
| `nas` | yes (primary host) | yes (secondary; pending cross-OS green run) | gated on D7/D9 Windows dataplane parity | consume-only (RustyBackup client) | consume-only (RustyBackup client) |
| `llm` | yes (primary host; GPU/accelerator on host) | yes (Apple-silicon inference; pending green run) | gated on D7/D9 | consume-only (RustyAI client) | consume-only (RustyAI client) |

Same gating philosophy as the existing host-capable roles: Linux is the proven primary host, macOS/Windows track their dataplane-parity readiness (`⛔ fail-closed` until live evidence), and **mobile is consume-only** — phones run the **RustyAI / RustyBackup client apps** against a NAS/LLM node hosted elsewhere; they never host. This adds two rows to [`../PlatformSupportMatrix.md`](../PlatformSupportMatrix.md) and the live `is_supported_for_platform` gate (`crates/rustynet-operator/src/role.rs`).

---

## 8) Security controls delta (extends SecurityMinimumBar §6.D)

The parent's ten §6.D controls all apply unchanged (transition matrix fail-closed, owner-signed capability changes, deploy-before-advertise, undeploy-before-revoke, tamper-evident audit, mobile role lock, platform-blocked fail-closed, read-only status). Service-hosting roles add **four category-specific controls** (proposed §6.E in SecurityMinimumBar):

| # | Control | Enforcement | Verification |
|---|---|---|---|
| E1 | Service endpoint binds tunnel-only | Listener bind address derived from the overlay interface; a config requesting `0.0.0.0`/LAN/public bind is rejected at startup, fail-closed | Unit test: non-tunnel bind config → daemon refuses to start; negative test: packet arriving on LAN/public iface for the service port → dropped |
| E2 | Default-deny per-peer service authorisation | `ContextualPolicySet::evaluate_with_membership` consulted for every new service session; empty/missing/stale policy ⇒ `Decision::Deny` | Truth-table test: no policy → deny; revoked peer → deny; explicitly-allowed peer → allow; tampered policy sig → deny |
| E3 | Service teardown precedes capability revocation | On `serves_nas`/`serves_llm` removal, daemon closes the listener and drops in-flight sessions BEFORE the capability leaves local state | Integration test: revoke while a peer holds an open session → session is severed and a new connect is refused before the bundle drops the flag |
| E4 | App-layer token cannot exceed signed policy | Any node-issued service token is checked against current signed policy on each use; a token outliving the peer's authorisation is rejected | Test: issue token → revoke peer in signed policy → token use denied (fail-closed), even before token TTL expiry |

Plus the inherited essentials restated for this category: capability requires owner signature (no self-promotion), no custom crypto, secrets never logged (service access tokens recorded only by thumbprint), and the verifier never consults `serves_nas`/`serves_llm` before validating signatures (capability is metadata, not authority).

Enforcement maps to a new `scripts/ci/service_hosting_role_gates.sh` plus the existing `role_taxonomy_gates.sh` / `role_transition_audit_gates.sh` extended for eight presets.

---

## 9) Build plan (insertion into the execution plan)

Add **D13 — Service-hosting role category (`nas`, `llm`)** to [`RustynetDataplaneExecutionPlan_2026-05-18.md`](./RustynetDataplaneExecutionPlan_2026-05-18.md) Track Alpha, after D12 (the six-role taxonomy must land first — D13 extends its preset table and transition validator).

| Slice | Scope | Prereq |
|---|---|---|
| **D13.a** | Capability + preset-table + transition-validator extension (this doc §3, §4); the service-binary predicates; eight-preset tests | D12.a |
| **D13.b** | Secure-exposure plumbing shared by both roles (this doc §5): tunnel-only listener helper, `TrafficContext::{NasService,LlmService}`, service-access policy evaluation seam, fail-closed health gating, service-access audit | D13.a |
| **D13.c** | `rustynet-nas` sibling service + `nas` role end-to-end — see [`NasNodeRoleDesign_2026-06-11.md`](./NasNodeRoleDesign_2026-06-11.md) | D13.b |
| **D13.d** | `rustynet-llm-gateway` sibling service + `llm` role end-to-end — see [`LlmNodeRoleDesign_2026-06-11.md`](./LlmNodeRoleDesign_2026-06-11.md) | D13.b |
| **D13.e** | Wizard/CLI eight-role surface, platform-matrix rows, service-deploy/undeploy installers for the two new siblings, audit + gates | D13.c, D13.d |

D13.c and D13.d are independent and can land in parallel once D13.b lands. The interface contracts for the future **RustyBackup** and **RustyAI** client apps are specified in the respective child docs (node-side contract only — the apps themselves are out of scope here).

---

## 10) Refactor inventory (delta only — see child docs for per-service detail)

| File | Change | Reason |
|---|---|---|
| `crates/rustynet-control/src/role_presets.rs` | Add `ServesNas`, `ServesLlm` to `Capability`; two rows in `ROLE_PRESET_TABLE`; service-binary predicates; transition-plan service flags; tests 6→8 | Preset/transition foundation |
| `crates/rustynet-control/src/roles.rs` | Add `RoleCapability::ServesNas/ServesLlm` + parse/`as_str`/aliases + tests | Capability wire taxonomy |
| `crates/rustynet-control/src/membership.rs` | Extend `node_capabilities` canonical pre-image (append-only) with the two flags | Signed advertisement |
| `crates/rustynet-policy/src/lib.rs` | Add `TrafficContext::NasService`, `TrafficContext::LlmService`; service-access truth-table tests | Default-deny authorisation |
| `crates/rustynetd/src/daemon.rs` | Tunnel-only service-listener lifecycle; service-access enforcement; fail-closed health gating; teardown-before-revoke | Runtime enforcement |
| `crates/rustynet-nas/` (new crate) | NAS sibling service | See NAS child doc |
| `crates/rustynet-llm-gateway/` (new crate) | LLM gateway sibling service | See LLM child doc |
| `crates/rustynet-cli/src/role_set.rs` (or `role_cli.rs`) | Dispatch `nas`/`llm` deploy/undeploy; service-binary install hooks | Transition orchestration |
| `crates/rustynet-operator/src/role.rs` | Per-platform eligibility for `nas`/`llm` | Platform gating |
| `start.sh`, operator menu | Eight-role prompt | Wizard surface |
| `documents/operations/PlatformSupportMatrix.md` | Two new role rows | Honest platform truth |
| `documents/SecurityMinimumBar.md` | New §6.E service-hosting controls (E1–E4) | Security baseline |
| `documents/Requirements.md` §6.1 | List `rustynet-nas`, `rustynet-llm-gateway` components | Component registry |
| `documents/operations/RustynetdServiceHardening.md` | Service-hosting hardening section | Per-role hardening |
| `documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md` | Add D13 | Execution ledger |
| `documents/operations/active/README.md` | Index the three new docs | Doc-tree map |

What does **NOT** change (deliberately preserved):

- **`NodeRole` enum** stays `Admin / Client / BlindExit`. No new primary.
- **WireGuard backend + tunnel crypto** untouched — service roles ride the existing tunnel.
- **Signing root + canonical signing flow** untouched — capability advertisement uses the same owner-signed membership path as `serves_exit`/`serves_relay`.
- **Trust verifiers** untouched — `serves_nas`/`serves_llm` never gate signature verification.
- **`rustynet-relay`** untouched — the new siblings are independent services with their own lifecycle.

---

## 11) Open questions

| Question | Default choice | What would re-open it |
|---|---|---|
| Should `nas` and `llm` be combinable on one box as a named 9th/10th preset? | No. Compose via `rustynet capability add` (operator-mode). Most homes run them on separate hardware (storage vs GPU). | If "one box does both" becomes the dominant pattern, promote a `homelab` composite preset. |
| Should the service endpoint ever be reachable off-mesh (e.g. a public ingress for RustyAI from anywhere)? | No. Tunnel-only, default-deny. Remote access means "join the mesh first," same as every other role. | Re-opening requires re-opening the §3 zero-ingress non-goals in the dataplane plan — stays "No". |
| Does the LLM gateway terminate the model API, or proxy to a separate inference engine? | Proxy/gateway to a co-located engine behind a process boundary (keeps Rust-first wrapper thin, model engine swappable). See LLM child doc. | If a pure-Rust inference path becomes first-class, revisit. |
| Should service-access authorisation be per-peer or per-group? | Both — reuse the existing policy group machinery; default-deny applies either way. | n/a (already general). |
| Should mobile ever *host* `nas`/`llm`? | No. Consume-only via RustyBackup/RustyAI. OS lifecycle + resource constraints forbid hosting. | Stable OS constraints; not expected to change. |

---

## 12) Definition of done

The service-hosting role category is "done" when:

- D13.a–e land on `main` with passing gates (standard workspace gates + `service_hosting_role_gates.sh` + eight-preset `role_taxonomy_gates.sh`).
- `rustynet role set nas` on a clean Debian 13 install with a data disk brings up a working NAS node (sibling service deployed, `serves_nas` advertised in signed membership, endpoint bound tunnel-only, default-deny until an owner-signed policy authorises a peer), and a second machine running the RustyBackup client contract reaches it **only** after signed authorisation.
- `rustynet role set llm` on a GPU host brings up a working LLM node exposing the inference API over the tunnel under the same default-deny posture, reachable by a RustyAI client contract only after authorisation.
- `rustynet role set admin` (owner signs the revocation) cleanly downgrades either node: listener torn down and sessions dropped before the capability is revoked, sibling service undeployed.
- The eight-role wizard presents `nas`/`llm` with correct per-platform gating; mobile shows consume-only.
- `PlatformSupportMatrix.md`, `SecurityMinimumBar.md` §6.E, and `Requirements.md` §6.1 reflect reality.
- Both child docs remain the source-of-truth for their respective roles.

---

## 13) Cross-references

- [`NodeRoleTaxonomy_2026-05-21.md`](./NodeRoleTaxonomy_2026-05-21.md) — parent taxonomy (six roles); this doc takes it to eight.
- [`NasNodeRoleDesign_2026-06-11.md`](./NasNodeRoleDesign_2026-06-11.md) — `nas` deep dive + RustyBackup contract.
- [`LlmNodeRoleDesign_2026-06-11.md`](./LlmNodeRoleDesign_2026-06-11.md) — `llm` deep dive + RustyAI contract.
- [`AnchorNodeRoleDesign_2026-05-21.md`](./AnchorNodeRoleDesign_2026-05-21.md) — pattern template (capability + co-deployed sibling + signed advertisement).
- [`RustynetDataplaneExecutionPlan_2026-05-18.md`](./RustynetDataplaneExecutionPlan_2026-05-18.md) — adds D13.
- [`MagicDnsSignedZoneSchema_2026-03-09.md`](./MagicDnsSignedZoneSchema_2026-03-09.md) — stable overlay names for service nodes.
- [`../PlatformSupportMatrix.md`](../PlatformSupportMatrix.md) — two new role rows.
- [`../RustynetdServiceHardening.md`](../RustynetdServiceHardening.md) — service-hosting hardening section.
- [`../../Requirements.md`](../../Requirements.md) — §6.1 component registry.
- [`../../SecurityMinimumBar.md`](../../SecurityMinimumBar.md) — new §6.E controls.
