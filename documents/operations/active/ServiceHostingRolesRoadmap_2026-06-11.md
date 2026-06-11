# Service-Hosting Roles Roadmap (`nas`, `llm`)

- Date: 2026-06-11
- Status: active (top-level roadmap for the NAS + LLM node-role program)
- Owner: Rustynet
- Purpose: a single front-door that sequences **all** the work to ship the two new service-hosting roles and points at the document that owns each piece. Read this first; follow the links for detail. This roadmap references every document in the program and is the place to track "where are we."

---

## 1) The document set (what each one is for)

| Document | Layer | Owns |
|---|---|---|
| [`NodeRoleTaxonomyExtension_2026-06-11.md`](./NodeRoleTaxonomyExtension_2026-06-11.md) | Design — category | The service-hosting role *category*: new capabilities, eight-role taxonomy, transition matrix, secure-exposure model (§5), security controls (§8 → SecurityMinimumBar §6.E), platform eligibility. Parent of the two role docs. |
| [`NasNodeRoleDesign_2026-06-11.md`](./NasNodeRoleDesign_2026-06-11.md) | Design — role | The `nas` role deep dive: `rustynet-nas` service, tunnel-only storage exposure, per-peer namespace, at-rest crypto, **RustyBackup** node-side contract, per-platform, controls, slices. |
| [`LlmNodeRoleDesign_2026-06-11.md`](./LlmNodeRoleDesign_2026-06-11.md) | Design — role | The `llm` role deep dive: `rustynet-llm-gateway`, identity-from-tunnel (no API key), gRPC/HTTP-2 streaming in-tunnel, exit-node coexistence, admin access governance, **RustyAI** node-side contract, industry survey, controls, slices. |
| [`ServiceHostingRolesDeltaPlan_2026-06-11.md`](./ServiceHostingRolesDeltaPlan_2026-06-11.md) | Delta — execution | Current-state vs target gaps, ordered slices D13.a–e, defect carry-overs, gate plan, live-lab readiness, delta-level DoD. The "what's missing and in what order" ledger. |
| **This roadmap** | Program | Sequencing across all of the above; milestones; dependencies; status tracking; how the future RustyAI/RustyBackup apps slot in. |

Supporting repo docs updated as part of the program (not new): `RustynetDataplaneExecutionPlan_2026-05-18.md` (adds D13), `PlatformSupportMatrix.md`, `SecurityMinimumBar.md` (§6.E), `Requirements.md` (§6.1), `RustynetdServiceHardening.md`, `SecretRedactionCoverage.md`, and the active-docs `README.md` index.

---

## 2) Guiding principles (do not violate)

1. **Trust is unchanged.** These roles change what an *authorised* peer can reach, never who is trusted. `serves_nas`/`serves_llm` are signed metadata, never authority. (Taxonomy ext §1.)
2. **Tunnel-only + default-deny + fail-closed**, one hardened path, no LAN/public escape hatch, no custom crypto. (Taxonomy ext §5.)
3. **Reuse, don't reinvent:** capability enum, policy `TrafficContext`, relay co-deploy lifecycle, exit-route logic, membership signing — all extended, not replaced.
4. **D12 first.** The six-role taxonomy (D12) is the substrate; D13 extends it. Do not start D13.a until D12.a is merged.
5. **Evidence over assertion.** Every control has a test; every role has a live-lab row.

---

## 3) Milestones (sequenced)

```
 M0  Prereq        D12 six-role taxonomy merged ............. (external dependency)
 M1  Foundation    D13.a presets+caps  →  D13.b exposure ..... unlocks both roles
 M2  NAS           D13.c rustynet-nas end-to-end ............. parallel with M3
 M3  LLM           D13.d rustynet-llm-gateway end-to-end ..... parallel with M2
 M4  Surface       D13.e wizard+matrix+security+gates ........ after M2 & M3
 M5  Evidence      Linux live-lab rows for nas & llm ......... promotes platform truth
 M6  Apps (future) RustyBackup + RustyAI clients ............. separate program, contract frozen at M2/M3
```

### M0 — Prerequisite (external)
D12 (the six-role user-selectable surface) must be merged: `ROLE_PRESET_TABLE`, `validate_transition`, wizard, and `role_taxonomy_gates.sh` are the things D13 extends. Owner: D12 ledger ([`NodeRoleTaxonomy_2026-05-21.md`](./NodeRoleTaxonomy_2026-05-21.md)). **Gate to start M1.**

### M1 — Foundation (D13.a + D13.b)
The capability/preset/transition extension and the shared secure-exposure plumbing. After M1, a service-hosting role can be expressed, signed, deployed-gated, and access-gated — but no concrete service exists yet. Owner: delta plan §3 (D13.a, D13.b). **Gate to start M2/M3.** Highest-leverage, lowest-glamour work; do it carefully — every later slice rides on the default-deny + fail-closed seam landed here.

### M2 — NAS role (D13.c)
`rustynet-nas` + daemon integration + `nas` preset + Linux install. Owner: [`NasNodeRoleDesign_2026-06-11.md`](./NasNodeRoleDesign_2026-06-11.md) §8 / delta plan D13.c. Parallel with M3.

### M3 — LLM role (D13.d)
`rustynet-llm-gateway` + daemon integration + exit-route exception + admin access verbs + `llm` preset + Linux install. Owner: [`LlmNodeRoleDesign_2026-06-11.md`](./LlmNodeRoleDesign_2026-06-11.md) §10 / delta plan D13.d. Parallel with M2. Carries the extra exit-coexistence and identity-from-tunnel work.

### M4 — Surface + security closeout (D13.e)
Eight-role wizard, platform matrix rows, SecurityMinimumBar §6.E, Requirements §6.1, hardening + redaction sections, the new gate scripts, transition-audit extension. Owner: delta plan D13.e. After M2 and M3.

### M5 — Live-lab evidence
Linux evidence rows for both roles (deploy → authorise → use → revoke-severance → undeploy); promote `PlatformSupportMatrix.md` from `⛔` to `✅` only on green. macOS/Windows tracked honestly. Owner: delta plan §5.

### M6 — Companion apps (future, separate program)
**RustyBackup** (consumes the NAS node-side contract, NAS doc §5) and **RustyAI** (consumes the LLM node-side contract, LLM doc §5) are built against the contracts frozen at M2/M3. Their own UI/architecture get their own design docs when that program starts; this roadmap only guarantees the stable node-side surfaces they target. Nothing in M0–M5 depends on M6.

---

## 4) Dependency graph

```
        D12 (M0)
           │
        D13.a ── D13.b   (M1)
                   │
          ┌────────┴────────┐
        D13.c (M2)        D13.d (M3)
          └────────┬────────┘
                 D13.e  (M4)
                   │
              live-lab    (M5)
                   │
        RustyBackup / RustyAI  (M6, future)
```

D13.c and D13.d share only D13.b; they touch different crates (`rustynet-nas` vs `rustynet-llm-gateway`) and can be built by separate streams in parallel.

---

## 5) Per-milestone gate checklist

Every milestone runs the standard workspace gates (CLAUDE.md §7): `cargo fmt`, `clippy -D warnings`, `check`, `test`, `cargo audit`, `cargo deny` — plus the slice-specific new gates from delta plan §4:

| Milestone | Adds these gates |
|---|---|
| M1 | extended `role_taxonomy_gates.sh` (8 presets); foundation truth-table + fail-closed-bind tests |
| M2 | `nas_default_deny_gates.sh` |
| M3 | `llm_default_deny_gates.sh`, `llm_exit_coexistence_gates.sh` |
| M4 | `service_hosting_role_gates.sh`, extended `role_transition_audit_gates.sh` |
| M5 | live-lab evidence rows appended + verified in `live_lab_run_matrix.csv` |

Fast local iteration: `cargo run -p rustynet-xtask -- gates` (fmt → check → clippy → test, fail-fast).

---

## 6) Risk register (program-level)

| Risk | Likelihood | Mitigation | Owner doc |
|---|---|---|---|
| D12 slips → D13 blocked | Medium | M1 explicitly gated on M0; do non-code design refinement while waiting | this roadmap §3 |
| Default-allow regression on empty policy | High impact | Truth-table test is the *first* test in D13.b, before any listener | delta plan §2 |
| Listener fail-open / non-tunnel bind | High impact | Fail-closed startup bind check (E1); negative tests | LLM/NAS doc §9/§7 |
| Revocation residue (served session survives) | High impact | Teardown-before-revoke (E3) + severance test | taxonomy ext §8 |
| Exit route swallows LLM traffic | Medium | Overlay-CIDR exception + precedence test (`llm_exit_coexistence_gates.sh`) | LLM doc §6 |
| Secret/prompt/file leakage in logs | Medium | Redaction coverage extended; logs carry ids/thumbprints/counts only | NAS §7 / LLM §9 |
| Scope creep into companion apps | Medium | Apps are M6, out of scope; only the node-side contract is frozen now | this roadmap §3 |

---

## 7) Status tracker (update in place as work lands)

| Item | State | Evidence / link |
|---|---|---|
| Design docs (taxonomy ext, NAS, LLM) | ✅ written 2026-06-11 | this folder |
| Delta plan (D13) | ✅ written 2026-06-11 | [`ServiceHostingRolesDeltaPlan_2026-06-11.md`](./ServiceHostingRolesDeltaPlan_2026-06-11.md) |
| Roadmap | ✅ this doc | — |
| D13 added to dataplane execution plan | ✅ 2026-06-11 | `RustynetDataplaneExecutionPlan_2026-05-18.md` §5.1 + per-phase D13 section |
| SecurityMinimumBar §6.E | ✅ 2026-06-11 | `../../SecurityMinimumBar.md` §6.E (E1–E4 + enforcement-point map) |
| M0 D12 prerequisite | ✅ verified in-tree 2026-06-11 | six-role `ROLE_PRESET_TABLE`, `transition_plan`, CLI verbs, wizard present; named role gate scripts were missing — see delta plan D13.a resolution 1 |
| M1 D13.a/b | ✅ D13.a landed 2026-06-11 · ✅ D13.b code+tests landed (daemon reconcile-loop wiring open — see delta plan D13.b status) | delta plan §3 + `scripts/ci/role_taxonomy_gates.sh` |
| M2 D13.c (nas) | ✅ crate+bin+installer+tests landed 2026-06-11 (daemon runtime integration + live evidence open) | delta plan D13.c status + `scripts/ci/nas_default_deny_gates.sh` |
| M3 D13.d (llm) | ✅ crate+bin+verbs+coexistence guard+tests landed 2026-06-11 (daemon runtime integration + live evidence open) | delta plan D13.d status + `scripts/ci/llm_default_deny_gates.sh` + `llm_exit_coexistence_gates.sh` |
| M4 D13.e surface | ✅ docs+gates landed 2026-06-11 (SecurityMinimumBar §6.E, Requirements §6.1, platform matrix ⛔ rows, hardening + redaction sections, `service_hosting_role_gates.sh`, `role_transition_audit_gates.sh`); wizard already lists eight presets via `RolePreset::all()` | this commit |
| M5 live-lab rows | ☐ not started | `../live_lab_run_matrix.csv` |
| M6 RustyBackup / RustyAI | ☐ future | separate program |

Legend: ✅ done · ☐ open · ⛔ blocked.

---

## 8) Definition of done (program)

The program is done when the delta-plan DoD (§6 there) is met **and**:

- All five new documents are merged and indexed; the supporting repo docs (execution plan, platform matrix, SecurityMinimumBar, Requirements, hardening, redaction) are updated in-change.
- `rustynet role set nas` and `rustynet role set llm` both work end-to-end on a clean Linux install, default-deny until owner-signed authorisation, with green live-lab evidence rows.
- The LLM node demonstrably streams to a RustyAI-contract client **with no API key**, identity derived from the tunnel, while the client's internet traffic egresses a selected exit node and LLM traffic stays intra-mesh.
- Admin grant/revoke of LLM (and NAS) access is signed, immediate, and fail-closed with session severance.
- The node-side RustyBackup and RustyAI contracts are frozen and documented, ready for the M6 app program.

---

## 9) Cross-references

- [`NodeRoleTaxonomyExtension_2026-06-11.md`](./NodeRoleTaxonomyExtension_2026-06-11.md) · [`NasNodeRoleDesign_2026-06-11.md`](./NasNodeRoleDesign_2026-06-11.md) · [`LlmNodeRoleDesign_2026-06-11.md`](./LlmNodeRoleDesign_2026-06-11.md) · [`ServiceHostingRolesDeltaPlan_2026-06-11.md`](./ServiceHostingRolesDeltaPlan_2026-06-11.md)
- [`NodeRoleTaxonomy_2026-05-21.md`](./NodeRoleTaxonomy_2026-05-21.md) · [`AnchorNodeRoleDesign_2026-05-21.md`](./AnchorNodeRoleDesign_2026-05-21.md) · [`RustynetDataplaneExecutionPlan_2026-05-18.md`](./RustynetDataplaneExecutionPlan_2026-05-18.md)
- [`../PlatformSupportMatrix.md`](../PlatformSupportMatrix.md) · [`../../SecurityMinimumBar.md`](../../SecurityMinimumBar.md) · [`../../Requirements.md`](../../Requirements.md)
