# Adversarial Review — `ServiceHostingRolesRoadmap_2026-06-11.md`

- Date: 2026-09-04
- Status: **UNTRUSTED adversarial review** — every claim below was re-derived from the tree at commit `2555b5f212c5f8ea9af9c6a8b31a2c830bd3cc9b` (docs-only review; no code was modified). Line numbers cited are at this commit.
- Subject: `documents/operations/active/ServiceHostingRolesRoadmap_2026-06-11.md` (the D13 `nas`+`llm` program roadmap), checked claim-by-claim against `crates/rustynet-nas/`, `crates/rustynet-llm-gateway/`, `crates/rustynet-control/`, `crates/rustynetd/`, `crates/rustynet-cli/`, `scripts/ci/`, and both live-lab ledgers.
- Method: every file:line, type/function name, crate, gate script, milestone (M0–M6), and commit SHA in the roadmap was grepped/read; SHAs were verified with `git cat-file -t` + `git merge-base --is-ancestor <sha> HEAD`.

---

## 1) Findings

### F1 — HIGH (stale gate, roadmap inherits it): `role_taxonomy_gates.sh` is broken against the current tree; roadmap's "8 presets" is stale (now 9)

- **Roadmap claim:** §5 M1 gate row — "extended `role_taxonomy_gates.sh` (8 presets)"; §7 M4 row — "wizard already lists eight presets via `RolePreset::all()`"; §3 M4 — "Eight-role wizard".
- **What the code shows:** `scripts/ci/role_taxonomy_gates.sh:31` greps `ROLE_PRESET_TABLE: \[RolePresetComposition; 8\]`, but the tree has `pub const ROLE_PRESET_TABLE: [RolePresetComposition; 9]` at `crates/rustynet-control/src/role_presets.rs:309`. The gate's drift-oracle filter `role_presets::tests::preset_table_has_exactly_eight_entries` (gate L69) now matches **zero tests** — the test is `preset_table_has_exactly_nine_entries` (`role_presets.rs:744`) — which trips the gate's own fail-closed `GATE DEFECT: test filter matched zero tests` path. `RolePreset::all()` returns `&'static [RolePreset; 9]` (`role_presets.rs:103`); the ninth preset (`blind_relay`) landed in `e50dc2b0` (2026-08-29, "feat(blind-relay): land phase 2 dedicated role scaffolding (§4.2)", verified ancestor of HEAD). The wizard iterates `RolePreset::all()` (`crates/rustynet-cli/src/role_cli.rs:825`), so it lists **nine** presets today.
- **Severity:** HIGH — the named M1 gate currently fails against the tree it is supposed to certify, and the roadmap's preset-count claims (M1 gate row, M4 wizard row, M4 "Eight-role wizard") are stale. The gate script itself needs an 8→9 refresh (code-adjacent; flagged, not fixed here — this review is docs-only).
- **Marker:** roadmap claims about D13.a landing are DONE ✅; the *count* language is STALE.

### F2 — MEDIUM (wrong file attribution): `evaluate_service_access` is not in `service_access_state.rs`

- **Roadmap claim:** §7.1 — "`crates/rustynetd/src/service_access_state.rs` — `derive_service_access_snapshot` + `evaluate_service_access` (test `evaluate_service_access_default_denies_and_honours_explicit_allow`, L957)".
- **What the code shows:** `derive_service_access_snapshot` **is** in `crates/rustynetd/src/service_access_state.rs:83` ✅, but `evaluate_service_access` is at `crates/rustynetd/src/service_exposure.rs:257`, with its test at `service_exposure.rs:957` (the roadmap's L957 matches *this* file, not the one named). `git log -S 'pub fn evaluate_service_access'` across both files shows exactly one commit — `493a994` (2026-06-11) — so the function has never lived in `service_access_state.rs` at any point.
- **Severity:** MEDIUM — a factually wrong citation in the §7.1 evidence map (the control itself is real and correctly described; only the file is wrong).

### F3 — MEDIUM (stale/forbidden ledger pointer): §5 M5 gate row cites the frozen bash-archive ledger

- **Roadmap claim:** §5 checklist — M5 adds "live-lab evidence rows appended + verified in `live_lab_run_matrix.csv`".
- **What the repo shows:** `live_lab_run_matrix.csv` is the frozen legacy bash-orchestrator archive (AGENTS.md §2: the bash engine was deleted in W5.7; nothing can append). The roadmap's own §7 M5 row was corrected on 2026-08-29 to point at `../live_lab_node_run_matrix.csv` (the live `--node` ledger) — **§5 was missed**, so the doc contradicts itself and still names a ledger that must never receive rows.
- **Severity:** MEDIUM — internal inconsistency + a forbidden-append target.

### F4 — MEDIUM (gap): the live `--node` ledger has no `nas`/`llm` stage columns, so M5 evidence has nowhere to land

- **Roadmap claim:** M5 — "Linux evidence rows for both roles (deploy → authorise → use → revoke-severance → undeploy)"; §7 M5 row points to the node ledger for them.
- **What the code shows:** the header of `documents/operations/live_lab_node_run_matrix.csv` contains **no** nas/llm stage columns — the only 7 columns matching `nas|llm` are substrings of `enrollment*` (verified by splitting the header on commas). Neither is there a service-hosting stage id in the `--node` stage registry vocabulary cited by the run matrix.
- **Severity:** MEDIUM — M5 is marked "next step" but its evidence vehicle does not exist yet; the roadmap (or the orchestrator stage registry) needs a defined nas/llm stage + ledger columns before the M5 run. Nothing in the roadmap flags this.

### F5 — LOW (stale count language, program-wide): "eight roles/presets" is now nine

- Covered in F1 for the roadmap's own text; note the sibling docs carry the same staleness (`NodeRoleTaxonomyExtension_2026-06-11.md` L6/L106/L159/L203 all say "eight"; index entries in `documents/operations/active/README.md` L107 likewise). The delta is blind_relay (2026-08-29), not an error against the roadmap's 2026-06-11 era — but the roadmap claims to be the live "where are we" tracker, and its §7 was edited as recently as 2026-08-29 without catching this.

### F6 — LOW (stale tool description): xtask gate order

- **Roadmap claim:** §5 — "`cargo run -p rustynet-xtask -- gates` (fmt → check → clippy → test, fail-fast)".
- **What the code shows:** current order is fmt → clippy → test; the standalone check stage exists only via `--with-check` (`crates/rustynet-xtask/src/main.rs:5-14`). Probably accurate when written (2026-06-11), stale now.

### F7 — INFO (expected line drift in §7.1; substance verified true)

The §7.1 evidence map disclaims "line numbers as of this commit" (2026-08-29). At the review commit the cited symbols all still exist but the lines moved:

| Roadmap cite | Actual now | Status |
|---|---|---|
| `tampered_service_hosting_capability_invalidates_signature` L3419 | `membership.rs:3418` | ✅ symbol, −1 line |
| `validate_node_role_membership_alignment` daemon.rs L2069 | `daemon.rs:2357` | ✅ symbol, drifted |
| BlindRelay refuses serves_* L2119–2137 | ~`daemon.rs:2401-2423` | ✅ arm exists |
| `materialize_service_access_state` L5327 | `daemon.rs:5632` | ✅ fn exists |
| Four commit points L5795/L8635/L9696/L10355 | `daemon.rs:6082/8979/10044/10730` | ✅ exactly four call sites |
| `validate_tunnel_only_bind` tests L657–710 | `service_exposure.rs:169` (fn), tests `:657`/`:710` region | ✅ |
| `service_hosting_view_serves_nothing_for_absent_or_inactive_node` L756 | `service_exposure.rs:756` | ✅ exact |

- **Severity:** INFO — drift is disclosed by the doc itself and no claim lost its referent (with the one exception promoted to F2).

---

## 2) Milestone audit — landed vs remaining (adversarial check of every ✅)

| Milestone | Roadmap says | Verdict against tree |
|---|---|---|
| M0 (D12 prereq) | ✅ verified in-tree | **DONE ✅** — `ROLE_PRESET_TABLE` (`role_presets.rs:309`), `validate_transition` (`:598`), `transition_plan` (`:603`), wizard + gate script exist. |
| M1 (D13.a+b) | ✅ complete incl. `de02cc2` | **DONE ✅** — `Capability::ServesNas`/`ServesLlm` (`role_presets.rs:225`, serde `:260-261`/`:286-287`), `capabilities_require_nas_binary`/`_llm_binary` (`:396`/`:404`), `ServiceKind` generalised (`:445-458`, now 4 kinds incl. Relay/Dns), `RoleCapability::ServesNas/ServesLlm` (`roles.rs:22-23`), `is_service_hosting_capability()` (`roles.rs:115`), blind_exit × service-hosting refusal in signed state (`membership.rs:~2720-2732`, "strictest default" comment verbatim), tamper test (`membership.rs:3418`), transition tests in the claimed L1537–1795 window (both boundary lines are `ServesNas` capability asserts). SHA `de02cc2` = real commit 2026-06-11 "materialise signed service-access state for nas/llm siblings", ancestor of HEAD. |
| M2 (D13.c nas) | ✅ crate+bin+installer+tests | **DONE ✅ (Linux)** — crate `crates/rustynet-nas/` with `[[bin]] rustynet-nas`; systemd unit `scripts/systemd/rustynet-nas.service`; real Linux installer dispatch (`crates/rustynet-cli/src/main.rs:19857-19870` → `ops_install_systemd_service::InstallServiceConfig::nas_install()`); non-Linux fails closed with explicit platform-matrix wording. Supporting SHAs `493a994` + `b2aad02` verified real, 2026-06-11, ancestors. |
| M3 (D13.d llm) | ✅ crate+bin+verbs+coexistence guard+tests | **DONE ✅ (Linux)** — `crates/rustynet-llm-gateway/` with `[[bin]] rustynet-llm-gateway`; `scripts/systemd/rustynet-llm-gateway.service`; executor `main.rs:19880+` (same fail-closed shape); admin verbs (`rustynet llm allow|deny|access list` per delta plan, `role_cli.rs`/`llm_cli.rs`); **exit-coexistence guard is real code**, not just a gate: `enforce_overlay_exception_for_exit_routes` (`crates/rustynetd/src/daemon.rs:2336`, fail-closed error "route set carries an exit default route but no mesh overlay routes"), plus `sanitize_dataplane_routes_for_node_role` (`daemon.rs:2309`). |
| M4 (D13.e surface) | ✅ docs+gates landed | **DONE ✅** — all six named gate scripts exist (`role_taxonomy_gates.sh`, `nas_default_deny_gates.sh`, `llm_default_deny_gates.sh`, `llm_exit_coexistence_gates.sh`, `service_hosting_role_gates.sh`, `role_transition_audit_gates.sh` — the last covers nas/llm); `SecurityMinimumBar.md` §6.E at L568 with E1–E4 (L578/609/641/664) incl. a "VERIFIED WIRED 2026-07-27" note; `Requirements.md` §6.1 (L211) defines both sibling services (L226-230) and the parity mandate (L146); `PlatformSupportMatrix.md` nas/llm ⛔ rows (L116-117); `ServiceHostingPhase2Design_2026-08-29.md` exists with OG-1/OG-2/OG-3 and P2-M1/M2/M3 as claimed. |
| M5 (live-lab) | ☐ open | **Correctly open ☐** — platform matrix still ⛔ pending live evidence; consistent. But see F4: no ledger schema to record it in. |
| M6 (apps) | ☐ future | Correctly deferred; no RustyBackup/RustyAI code claimed or found (correct). |

No milestone ✅ in §7 was found to be an overclaim: every "landed" marker traces to real code. The staleness is all in *counts, files, pointers, and line numbers*, not in what shipped.

---

## 3) Fail-closed risk assessment

- **The roadmap proposes nothing that weakens a fail-closed control.** Its one self-identified hazard — "Default-allow regression on empty policy" (§6, risk row 2) — is enforced, not just planned: `evaluate_service_access_default_denies_and_honours_explicit_allow` (`service_exposure.rs:957`), explicit empty-grant ⇒ deny-all, `force_deny_all` as the write-failure fallback (`service_access_state.rs:219`, test `:648`), and the policy-layer "empty-context hardening" (a rule with an empty `contexts` list never matches service contexts — delta plan §3 D13.b status; `TrafficContext::NasService/LlmService` at `crates/rustynet-policy/src/lib.rs:22/26`).
- **Co-location refusal is double-enforced** (preset transition level: `role_presets.rs:1197`/`:1226` "every transition leaving blind_exit is blocked"; signed-state level: `membership.rs:~2726`).
- **The §7.1 flags are still true and should stay flagged:** `ServiceExposureController` (`service_exposure.rs:364`, `admit_session` `:463`) remains unit-tested scaffolding not yet driven by the daemon runtime — the daemon wiring is Phase-2's P2-M1/M2/M3, per `ServiceHostingPhase2Design_2026-08-29.md` (whose OG-1 resolution is deny-on-absent scopes: "no scope entry ⇒ every model denied", Phase2Design L31). Revocation severance rests on the binaries' per-frame re-read of materialised deny state, which exists (`grants.v1`/`peers.v1`/`scopes.v1` constants, `service_access_state.rs:47-49`; four materialisation call sites).
- **Already-exists-under-a-different-name check:** only F2 (right name, wrong file). Everything else the roadmap sequences exists under exactly the names it uses — no duplicated or renamed mechanisms found that the roadmap fails to point at.

---

## 4) Verified correct (spot-checked claims that hold)

- Document set: all five program docs exist and are indexed; supporting docs `RustynetdServiceHardening.md`, `SecretRedactionCoverage.md` exist under `documents/operations/`.
- SHAs: `de02cc2`, `493a994`, `b2aad02` — all real commits, all ancestors of HEAD, all dated 2026-06-11, messages matching their attributed work.
- Section cites resolve: LLM doc §5 (`RustyAI` contract, L126), §6 (exit coexistence, L159), §9 (controls, L216), §10 (build slices → D13.d, L238); NAS doc §5 (`RustyBackup`, L92), §7 (controls, L151), §8 (→ D13.c, L170); delta plan §0–§7; taxonomy ext §5 (L132), §8 (L176); roadmap §3 owner pointers match.
- Design-doc line quotes: NasNodeRoleDesign L204/L29 and LlmNodeRoleDesign L274/L30 ("Deliberately unchanged: `NodeRole` enum …") are verbatim correct.
- §7.1's daemon-side claim: `validate_node_role_membership_alignment` correctly has no nas/llm arm (they are deliberately not `NodeRole` primaries) and its BlindRelay arm refuses serves_* co-location.
- §7 M5 ledger pointer (corrected 2026-08-29) names the right live ledger — it is §5 (F3) that was missed.
- M0 "six-role" wording is accurate for D12 (the substrate); M4's ⛔-rows claim matches `PlatformSupportMatrix.md:116-117`.
- The roadmap's transport wording (§1: "gRPC/HTTP-2 streaming") describes the *design doc*; the landed transport is the hardened framed binary protocol (delta plan D13.d "Transport resolution"), and the DoD's "streams … with no API key" is transport-agnostic — no contradiction, but a reader should not expect gRPC on the wire.

---

## 5) Considered, no issue

- `ServiceKind::all()` now has 4 variants (Relay/Nas/Llm/Dns) — the roadmap never claims "only two service kinds"; not a defect.
- `Requirements.md` §6.1 does not use `serves_nas` verbatim — it names the components instead; the roadmap's §6.1 cite is still valid.
- `de02cc2` attribution to "daemon access-state materialisation" matches the commit message exactly.
- The roadmap's dependency graph (D12 → D13.a/b → c ∥ d → e → live-lab → apps) matches the delta plan's slice prereqs (delta plan §3 L55, L95) — no false edge found.
- Roadmap risk register owners all point at real sections (LLM/NAS §9/§7, taxonomy ext §8, LLM §6, delta plan §2).

---

## 6) Verdict

The roadmap's M0–M4 "landed" claims verify against the tree, its M5/M6 honesty is intact, and no proposed work weakens a fail-closed control — but it **needs a staleness refresh**: fix the 8→9 preset/gate drift (F1 — `role_taxonomy_gates.sh` currently fails against the tree it certifies), the `evaluate_service_access` file cite (F2), the §5 frozen-ledger pointer (F3), and give M5 a nas/llm ledger-schema target (F4) before its evidence run.

---

## 7) Self-verification of this review

Per the review brief, four key citations were re-grepped immediately before writing (all confirmed at commit `2555b5f2`):

1. `role_presets.rs:309` → `pub const ROLE_PRESET_TABLE: [RolePresetComposition; 9] = [`
2. `service_exposure.rs:257` → `pub fn evaluate_service_access(`
3. `scripts/ci/role_taxonomy_gates.sh:31` → `rg -q 'ROLE_PRESET_TABLE: \[RolePresetComposition; 8\]' …`
4. `role_presets.rs:744` → `fn preset_table_has_exactly_nine_entries() {`

Plus a fifth spot-check: `membership.rs:3418` → `fn tampered_service_hosting_capability_invalidates_signature() {`.
