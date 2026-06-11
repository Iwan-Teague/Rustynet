# Service-Hosting Roles Delta Plan (`nas`, `llm`) — D13

- Date: 2026-06-11
- Status: active (delta ledger for implementing the two service-hosting node roles)
- Owner: Rustynet
- Design source-of-truth: [`NodeRoleTaxonomyExtension_2026-06-11.md`](./NodeRoleTaxonomyExtension_2026-06-11.md) (category), [`NasNodeRoleDesign_2026-06-11.md`](./NasNodeRoleDesign_2026-06-11.md), [`LlmNodeRoleDesign_2026-06-11.md`](./LlmNodeRoleDesign_2026-06-11.md).
- Relationship to other ledgers: this is the **delta plan** (what is missing today, in what order to close it, with evidence) that drives **D13** in [`RustynetDataplaneExecutionPlan_2026-05-18.md`](./RustynetDataplaneExecutionPlan_2026-05-18.md). It plays the same role for `nas`/`llm` that [`PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md`](./PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md) plays for traversal/relay. The design docs say *what and why*; this says *what's not there yet and the order to build it*.

---

## 0) How to read this document

This is a gap-driven ledger, not a design doc. It assumes the three design docs are read. Each item is phrased as a **delta**: current state → target state → the slice that closes it → the evidence that proves it closed. Precedence: where this conflicts with the design docs on *intent*, the design docs win; where it conflicts on *sequencing/evidence*, this wins.

Prerequisite: **D12 (six-role taxonomy) must be landed** — D13 extends `ROLE_PRESET_TABLE`, `validate_transition`, the wizard, and the gate scripts that D12 introduces. If D12 is not yet merged, D13.a is blocked on it.

---

## 1) Current-state baseline (verified against the code, 2026-06-11)

| Area | What exists today | Gap for service-hosting roles |
|---|---|---|
| Preset model | `RolePreset` (6 variants), `ROLE_PRESET_TABLE`, `transition_plan`/`validate_transition` in `crates/rustynet-control/src/role_presets.rs`; `Capability` enum with `ServesExit`/`ServesRelay`/`anchor.*` | No `nas`/`llm` presets; no `ServesNas`/`ServesLlm` capability; no nas/llm service-binary predicates; transition struct has only relay deploy/undeploy flags |
| Capability wire taxonomy | `RoleCapability` enum + parse/`as_str`/aliases in `crates/rustynet-control/src/roles.rs` | No `ServesNas`/`ServesLlm` variants or parse arms |
| Signed membership | `node_capabilities` canonical pre-image in `crates/rustynet-control/src/membership.rs` (append-only) | Two new flags not in the pre-image |
| Policy engine | `PolicySet`/`ContextualPolicySet` with default-`Decision::Deny`; `TrafficContext` enum; `evaluate_with_membership` in `crates/rustynet-policy/src/lib.rs` | No `NasService`/`LlmService` traffic contexts; no model/quota scoping fields |
| Daemon | `NodeRole` (Admin/Client/BlindExit) at `daemon.rs:1195`; `is_serving_exit_node`; route sanitisation `sanitize_dataplane_routes_for_node_role`; IPC role/capability verbs (D12) | No tunnel-only service-listener lifecycle; no service-access gate; no fail-closed service health gate; no teardown-before-revoke for services; **no overlay-CIDR exception in exit-route application** |
| Sibling-service deploy | `rustynet-relay` co-deploy via `ops install-systemd` (Linux), launchd, SCM | No `rustynet-nas` / `rustynet-llm-gateway` crates; no co-deploy/undeploy for them |
| Platform gate | `is_supported_for_platform` in `crates/rustynet-operator/src/role.rs` | No `nas`/`llm` rows |
| Wizard | `start.sh` + operator menu six-role prompt (D12) | No `nas`/`llm` options |
| Security baseline | SecurityMinimumBar §6.D role-transition controls | No §6.E service-hosting controls (E1–E4) |
| Gates | `role_taxonomy_gates.sh` etc. (D12) | No `service_hosting_role_gates.sh`; six-preset assertions need to become eight |

No service-hosting plumbing exists yet; this is net-new on top of the D12 preset machinery. Nothing in the current tree blocks the design — the seams (capability enum, policy `TrafficContext`, relay co-deploy pattern, exit-route logic) are all the right shape to extend.

---

## 2) Defects / risks to avoid (carry-over lessons)

These come from the existing security ledgers ([`SecurityAndQualityAudit_2026-06-10.md`](./SecurityAndQualityAudit_2026-06-10.md), [`SecurityReview_2026-05-24.md`](./SecurityReview_2026-05-24.md)) and apply directly to service-hosting roles:

| Risk | Source lesson | Mitigation in D13 |
|---|---|---|
| Default-allow on empty policy | RN-11 / "permissive-on-empty" findings | Service-access gate must inherit the engine's `Decision::Deny` default; D13.b adds an explicit "no policy → deny" truth-table test before any listener is wired |
| Fail-open listener | killswitch fail-open findings (RN-03/04/10) | Service listener binds tunnel-only and refuses non-tunnel bind at startup (fail-closed); health failure closes the endpoint, never degrades to open |
| Revocation that leaves residue | exit-NAT residue release-blocker (§6.D-7) | Teardown-before-revoke (E3): listener + sessions dropped before capability leaves local state; a test asserts no residual served session after revoke |
| Non-deterministic reducer blocks revocation | AUDIT-040 | Capability add/remove for `serves_nas`/`serves_llm` must round-trip through the reducer deterministically; covered by membership round-trip tests |
| Secret/content leakage in logs | secret-hygiene findings | Service logs carry only ids/thumbprints/counts; never tokens, file contents, prompts, or completions |
| Unbounded/malformed input | HTTP-body-unbounded findings | Gateway/NAS wire decoders length-bounded, deny-on-malformed, fuzzed (uploads + prompts are attacker-influenced) |

---

## 3) Slice plan (ordered, with prereqs and evidence)

D13.a → D13.b are the foundation and must land first. D13.c (`nas`) and D13.d (`llm`) are independent and parallelisable after D13.b. D13.e closes the surface.

### D13.a — Preset + capability + transition foundation
- **Prereq:** D12.a landed.
- **Change:** add `ServesNas`/`ServesLlm` to `Capability` (role_presets.rs) and `RoleCapability` (roles.rs) with wire strings `serves_nas`/`serves_llm`, parse arms, aliases; add `nas`/`llm` rows to `ROLE_PRESET_TABLE`; add `requires_nas_binary`/`requires_llm_binary` (or the generalised `service_deploys`/`service_undeploys` on `TransitionPlan`); extend `node_capabilities` canonical pre-image (append-only).
- **Evidence:** eight-preset table tests; `transition_matrix_matches_taxonomy_doc` extended to 8×8 and matching [`NodeRoleTaxonomyExtension_2026-06-11.md`](./NodeRoleTaxonomyExtension_2026-06-11.md) §4; tamper test on each new capability flag; membership round-trip with the new flags.
- **Status: ✅ landed 2026-06-11.** All evidence present: `preset_table_has_exactly_eight_entries`, 8×8 `transition_matrix_matches_taxonomy_doc` + new `service_lifecycle_matrix_matches_taxonomy_extension_doc` (deploy/undeploy oracle from taxonomy ext §4), `tampered_service_hosting_capability_invalidates_signature` (flip + drop variants, untampered control), `set_node_capabilities_update_round_trips_service_hosting_flags`, append-only ordering pins (`capability_ordering_is_append_only`, `service_hosting_capabilities_sort_after_existing_variants`). New `scripts/ci/role_taxonomy_gates.sh` wraps the eight-preset suites.
- **Resolutions recorded while landing D13.a** (per §0 precedence — code reality wins over doc assumption; strictest-secure default where docs were silent):
  1. **`role_taxonomy_gates.sh` / `role_transition_audit_gates.sh` did not exist** — D12 landed its assertions as cargo tests, not named gate scripts (real D12-era role gates: `anchor_role_gates.sh`, `role_auth_matrix_gates.sh`, `cross_platform_role_gates.sh`). D13.a therefore **created** `role_taxonomy_gates.sh` (eight-preset suites across control/cli/operator/mcp); `role_transition_audit_gates.sh` will be created (not extended) in D13.e.
  2. **Generalised lifecycle chosen** (taxonomy ext §3.4 preferred form): `ServiceKind { Relay, Nas, Llm }` + `service_deploys`/`service_undeploys: Vec<ServiceKind>` on `TransitionPlan`, **replacing** `requires_relay_deploy`/`requires_relay_undeploy`. The doc-named predicates `capabilities_require_nas_binary`/`capabilities_require_llm_binary` exist alongside `capabilities_require_relay_binary`; `requires_service_deploy/undeploy(kind)` helper methods preserve call-site ergonomics. Consumers updated: `role_cli::plan_concrete_actions`, MCP repo-context mirror.
  3. **Append-only enum placement:** `ServesNas`/`ServesLlm` append at the END of both `Capability` and `RoleCapability` — the derived `Ord` feeds canonical (signed) serialisation, so existing canonical payloads are byte-identical; pinned by tests.
  4. **`blind_exit` × `serves_nas`/`serves_llm` forbidden** in `validate_membership_node_capabilities` (strictest default; mirrors the existing anchor×blind_exit rule — the hardened minimal-surface exit never co-hosts an application service; the preset table cannot produce the combination).
  5. **Wizard canonical order** (`RolePreset::all()`): anchor, admin, exit, relay, **nas, llm**, client, blind_exit — hosting roles grouped, passive presets last.
  6. **Fail-closed executor until services exist:** `role set nas|llm` planner emits `DeployNasService`/`DeployLlmService`, and `main.rs::execute_platform_{nas,llm}_service_action` fails closed (`blocked_by_service_install_path`) on every OS until D13.c/D13.d land the hardened installers — mirroring the in-tree pre-D11.a `blocked_by_capability_schema` precedent. Deploy-before-advertise is preserved by failing the deploy.
  7. **Platform-eligibility seam correction:** `is_supported_for_platform` lives in `crates/rustynet-cli/src/vm_lab/orchestrator/role.rs` (not `rustynet-operator/src/role.rs` as the refactor inventory implied). Operator-side `RolePreset` (SETUP_ROLE_PRESET parsing) gained `nas`/`llm` (→ Admin primary) in D13.a; the lab-role/platform-gate rows land with D13.c/d, and the MCP `role_support` mirror reports nas/llm **⛔ fail-closed on all hosts** until live evidence.
  8. **Pre-existing planner gap fixed while generalising:** the generic signed-membership arm of `plan_concrete_actions` omitted the exit-capability side-effects, so leaving `exit` for any capability preset (`exit → relay/anchor`, inherited by `exit → nas/llm`) left 0.0.0.0/0 advertised and the exit preflight running after `serves_exit` revocation — §6.D control 7 territory. D13.a adds `AdvertiseDefaultRoute`+`DeployExitService` on `serves_exit` gain and `UndeployExitService`+`RetractDefaultRoute` on loss to the generic arm (same ordering as the explicit admin↔exit cells), pinned by exact-order tests (`exit_to_nas_tears_down_exit_serving_in_order`, `exit_to_relay_tears_down_exit_serving`, `relay_to_exit_activates_exit_serving_and_undeploys_relay`).
  9. **Inherited (unchanged) relay-precedent behaviours, noted for D13.b/c:** (a) `resolve_preset_from_status` still resolves from `(primary, serving_exit)` only — an active nas/llm/relay/anchor node reports as `admin` until the membership-backed resolver lands (the daemon-side capability view is D13.b scope); (b) in the generic arm the `NODE_ROLE` env write precedes the service deploy, so a failed deploy from `client → nas|llm` leaves the primary elevated to admin with no capability advertised — same as `client → relay` today; signed state is untouched and the trust boundary stays fail-closed.

### D13.b — Shared secure-exposure plumbing
- **Prereq:** D13.a.
- **Change:** tunnel-only listener helper (bind derived from overlay interface; non-tunnel bind → fail-closed startup error); `TrafficContext::NasService`/`LlmService`; daemon-mediated peer-identity handoff to a sibling service; service-access evaluation seam over `ContextualPolicySet::evaluate_with_membership`; fail-closed health gate; teardown-before-revoke hook; service-access audit entries.
- **Evidence:** truth-table test (no policy → deny; allow → that peer; revoke → deny; tampered sig → deny); startup-refuses-non-tunnel-bind test; teardown-before-revoke unit test with a stub service.

### D13.c — `nas` role end-to-end
- **Prereq:** D13.b. Detail: [`NasNodeRoleDesign_2026-06-11.md`](./NasNodeRoleDesign_2026-06-11.md) §8.
- **Change:** `rustynet-nas` crate (protocol, per-peer namespace, quota, at-rest AEAD, health); daemon integration; `nas` preset deploy/undeploy; Linux systemd install + nftables NAS table; macOS/Windows scaffolds (gated).
- **Evidence:** `nas_default_deny_gates.sh`; at-rest-ciphertext test; per-peer namespace isolation test; Debian 13 `role set nas` → authorise device → backup+restore → revoke (session severed) live evidence row in `live_lab_run_matrix.csv`.

### D13.d — `llm` role end-to-end
- **Prereq:** D13.b. Detail: [`LlmNodeRoleDesign_2026-06-11.md`](./LlmNodeRoleDesign_2026-06-11.md) §10.
- **Change:** `rustynet-llm-gateway` crate (gRPC/HTTP-2 streaming, loopback engine proxy, identity-from-tunnel, model/quota/rate enforcement, optional session token); daemon integration; **overlay-CIDR exit-route exception** in exit-route application + `sanitize_dataplane_routes_for_node_role`; `llm` preset deploy/undeploy; admin verbs `rustynet llm allow/deny/access list`; Linux install + nftables LLM table; macOS/Windows scaffolds (gated).
- **Evidence:** `llm_default_deny_gates.sh`; `llm_exit_coexistence_gates.sh` (exit selected → LLM traffic intra-mesh, internet via exit); no-API-key streaming test against a mock engine; revoke-mid-stream severance test; GPU-host live evidence row.

### D13.e — Surface, audit, gates closeout
- **Prereq:** D13.c, D13.d.
- **Change:** eight-role wizard (`start.sh` + operator menu) with platform gating + "no device authorised yet" guidance + accelerator/data-disk notes; `PlatformSupportMatrix.md` rows; `SecurityMinimumBar.md` §6.E; `Requirements.md` §6.1 components; `RustynetdServiceHardening.md` + `SecretRedactionCoverage.md` sections; `service_hosting_role_gates.sh`; transition-audit gate extended to eight presets.
- **Evidence:** wizard golden test (eight options, correct gating); audit gate green; full standard workspace gates green.

---

## 4) Gate plan

Standard workspace gates (CLAUDE.md §7) for every slice, plus:

| Gate (new) | Covers | Lands with |
|---|---|---|
| `service_hosting_role_gates.sh` | E1–E4 category controls; eight-preset transition matrix; deploy/undeploy lifecycle (Linux live; macOS smoke; Windows gated) | D13.e |
| `nas_default_deny_gates.sh` | NAS §7 truth table; namespace isolation; at-rest ciphertext | D13.c |
| `llm_default_deny_gates.sh` | LLM §9 truth table; model/quota scoping; revoke-mid-stream | D13.d |
| `llm_exit_coexistence_gates.sh` | overlay-CIDR exit-route precedence | D13.d |
| `role_taxonomy_gates.sh` (extend) | six→eight presets | D13.a |
| `role_transition_audit_gates.sh` (extend) | nas/llm transition audit entries | D13.e |

---

## 5) Live-lab readiness

Both roles need a live-lab evidence row per the standard discipline ([`../LiveLabRunMatrix.md`](../LiveLabRunMatrix.md)):

- **`nas`:** Linux UTM guest with a spare data disk; stages = deploy → advertise → authorise peer → backup → restore → revoke (severance) → undeploy. macOS/Windows assigned but `⛔` until cross-OS green.
- **`llm`:** Linux (or Apple-silicon macOS) guest able to load a small model; stages = deploy → advertise → authorise peer → stream completion (no API key) → exit-coexistence check → revoke (severance) → undeploy. GPU not required for the harness if a tiny CPU model stands in for the engine.
- Use the existing probe-and-recover runbook before retrying a failed orchestrator run; append the matrix row after every evidence run and verify it exists (CLAUDE.md §10.9).

UTM inventory + orchestrator wrappers: [`UTMVirtualMachineInventory_2026-03-31.md`](./UTMVirtualMachineInventory_2026-03-31.md).

---

## 6) Definition of done (delta-level)

- All D13.a–e slices merged on `main` with standard + new gates green.
- Both roles have a green Linux live-lab evidence row (deploy → authorise → use → revoke-severance → undeploy); macOS/Windows honestly `⛔` until their cross-OS runs.
- The eight-role matrix in code matches the design-doc matrix (drift test green).
- Default-deny, fail-closed, teardown-before-revoke, and no-secret-logging proven by tests, not assertion.
- Design docs, `PlatformSupportMatrix.md`, `SecurityMinimumBar.md` §6.E, `Requirements.md` §6.1, and the indexes all updated in-change.

---

## 7) Cross-references

- Design: [`NodeRoleTaxonomyExtension_2026-06-11.md`](./NodeRoleTaxonomyExtension_2026-06-11.md) · [`NasNodeRoleDesign_2026-06-11.md`](./NasNodeRoleDesign_2026-06-11.md) · [`LlmNodeRoleDesign_2026-06-11.md`](./LlmNodeRoleDesign_2026-06-11.md)
- Roadmap: [`ServiceHostingRolesRoadmap_2026-06-11.md`](./ServiceHostingRolesRoadmap_2026-06-11.md)
- Pattern precedent: [`AnchorNodeRoleDesign_2026-05-21.md`](./AnchorNodeRoleDesign_2026-05-21.md) · [`NodeRoleTaxonomy_2026-05-21.md`](./NodeRoleTaxonomy_2026-05-21.md) · [`PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md`](./PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md)
- Execution: [`RustynetDataplaneExecutionPlan_2026-05-18.md`](./RustynetDataplaneExecutionPlan_2026-05-18.md) (D13)
- Risk carry-over: [`SecurityAndQualityAudit_2026-06-10.md`](./SecurityAndQualityAudit_2026-06-10.md) · [`SecurityReview_2026-05-24.md`](./SecurityReview_2026-05-24.md)
- Evidence: [`../LiveLabRunMatrix.md`](../LiveLabRunMatrix.md) · [`UTMVirtualMachineInventory_2026-03-31.md`](./UTMVirtualMachineInventory_2026-03-31.md)
