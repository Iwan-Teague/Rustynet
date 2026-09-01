# Anchor Platform Selector Propagation Investigation — 2026-08-31

**Question:** Why do `StageId::MacosAnchorProfileDeploy`, `MacosAnchorBundlePullValidation`, and
`MacosAnchorPortMappingAuthorityValidation` still not dispatch when a run is launched via the
`ai_lab_run` MCP tool with `anchor_platform: "macos"` and `skip_linux_live_suite: true`, even though
commit `e3297391` added the MAC-D3 plan exception plus unit test
`macos_anchor_validator_stages_follow_the_live_suite_gate`?

**Answer (one line):** On the default Rust `--node` engine path, the MCP layer consumes
`anchor_platform` only as a *role assignment* (via `--node macos-utm-1:anchor`) and never forwards the
raw `--anchor-platform macos` CLI flag — while the native orchestrator's plan-structure election for
the three macOS anchor validator stages reads *only* the raw flag. The selector's role half propagates;
its plan-election half is dropped at the MCP argv-synthesis boundary.

Status: investigation complete, root cause confirmed against real code and a real run. This document
records the traced chain, the exact break point, the fix direction, and the blast radius on the other
role selectors. No code was changed by this investigation.

---

## 1) Evidence from the triggering run

Run directory: `/Users/iwan/Desktop/Rustynet/state/deepseek-lab-labrun-1788261250837-15328-10`
(`ai_lab_run` job `labrun-1788261250837-15328-10`, ledger run `livelab-1788261812-690fc35b66d1`,
commit `690fc35b66d1…`, clean tree, macOS node `macos-utm-1` in the anchor role).

- `state/stages.tsv` shows **only `anchor_validation`** for the macOS anchor cell (reported `skip`).
  The three `MacosAnchor*` stages are entirely **absent** — not failed, not skipped-by-gate, but
  *never planned*. That is the signature of `PlanBuilder.anchor_platform_macos == false` at plan
  build time: under `skip_live_suite`, the stage-include filter removes them from the plan before
  any stage record is written.
- `orchestration/stage_manifest.json` selectors block: `"anchor_platform": ""`,
  `"skip_linux_live_suite": true`, `"wants_macos": true`. The three `MacosAnchor*` entries carry
  `"enabled": false, "skip_reason": "not part of the Rust state-machine plan for this run"`.
  `anchor_validation` itself is enabled (it ran, and reported a skip outcome because its validator
  preconditions — the anchor validators elected under MAC-D3 — never executed).
- `state/nodes.tsv:3`: `macos-utm-1  192.168.65.101  macos-utm-1-bootstrap  anchor  macos` — the
  selector **did** become a role assignment.
- `state/orchestration_context.json:22`: `"role": "Anchor"` for the macOS node.

Conclusion: the caller's `anchor_platform: "macos"` survived as a *role* but was lost as the
*raw flag* that the plan builder reads. The loss happened upstream of the CLI parser (the parsed
config's `anchor_platform` was empty at orchestration time).

---

## 2) Traced chain, hop by hop

### Hop 1 — MCP tool handler: `crates/rustynet-mcp/src/bin/ai_agent.rs`

- Tool schema declares `anchor_platform` (and the sibling role selectors) — `ai_agent.rs:7597`;
  argument validation via `validate_role_platform("anchor_platform")` at `ai_agent.rs:3779`.
- `rust_engine` defaults to **true** (`ai_agent.rs:3809-3813`, "default to Rust engine per F9-7").
- `build_orchestrator_args` (`ai_agent.rs` ~6378–6510) builds the orchestrator argv:
  - **rust_engine path (the default):** role selectors are consumed ONLY by
    `synthesize_rust_node_args` (`ai_agent.rs` ~6311–6376), which converts them into
    `--node <alias>:<role>` assignments — `anchor_platform: "macos"` becomes
    `--node macos-utm-1:anchor` (macOS → `anchor`, plus exit/relay/admin/blind_exit/client tokens;
    Linux `exit_vm`/`client_vm`/`entry_vm` keep fixed roles; order exit, client, entry, macos, windows).
  - **`if !rust_engine` branch:** the raw flags `--exit-platform`, `--relay-platform`,
    `--anchor-platform` (~6476-6477), `--admin-platform`, `--blind-exit-platform` are emitted —
    but this branch is dead by default since the legacy bash orchestrator was retired in W5.7.
  - `--skip-linux-live-suite` **is** forwarded unconditionally when set (~6500-6504), which is why
    the skip flag took effect in the run while the election flag did not.
  - Other unconditional rust-engine-path args: `--trust-inventory-ready`, `--skip-gates`,
    `--skip-soak`, `--source-mode working-tree`, `--node …`, optional `--rebuild-nodes`.
- The parallel `rustynet-mcp-lab-state` tool (`crates/rustynet-mcp/src/bin/lab_state.rs`,
  `start_live_lab_run`) maps `anchor_platform` → `--anchor-platform` (`lab_state.rs:6493`, map at
  :6491–6495) — but per its own comments (:6444, :11570) that raw-flag mapping serves the retired
  bash arm; the rust-engine arm synthesizes `--node` the same way. The break is therefore in the
  shared design, visible at `build_orchestrator_args`.

### Hop 2 — CLI parser: `crates/rustynet-cli/src/main.rs`

- `--anchor-platform` → `anchor_platform: parser.value("--anchor-platform")` (`main.rs:4477`);
  usage text at `main.rs:20530` (`--anchor-platform <linux|macos|windows>` for
  `vm-lab-orchestrate-live-lab`).
- `--node alias:role` is parsed **independently** into `node_assignments` via `parse_node_role_arg`
  (`main.rs:4462-4471`).
- The two config fields are never reconciled: nothing derives `config.anchor_platform` from an
  Anchor-role `node_assignment`, and vice versa. The parser is faithful; it received no
  `--anchor-platform` because hop 1 never sent one.

### Hop 3 — Orchestrator: `crates/rustynet-cli/src/vm_lab/orchestrator/native.rs`

- `ctx.assignments` loaded from `config.node_assignments` (`native.rs:223`) — the synthesized
  `--node macos-utm-1:anchor` lands here. ✔ role half propagates.
- `augment_assignments_from_platform_selectors` (`native.rs:240-250` call; def ~:963-1010) consumes
  `config.exit/relay/anchor/admin/blind_exit_platform` **only** to append role assignments for the
  first *unassigned* inventory entry of the matching platform (hard error if none). With
  `config.anchor_platform == ""` it is a no-op — harmless, because the role was already assigned.
- **The plan builder** (`native.rs:329-335`) is constructed with
  `anchor_platform_macos = config.anchor_platform.as_deref() == Some("macos")` (the MAC-D3 comment:
  "keep the three macOS anchor validator stages in the plan when a macOS anchor is elected, even
  under skip_live_suite"). **This reads only the raw flag.** With the flag empty, the election is
  false.
- Election bookkeeping: `ctx.macos_anchor_validators_elected` = same flag condition AND all three
  `MacosAnchor*` StageIds present in the plan — preliminary at `native.rs:261`, post-plan tightening
  at `native.rs:377-388` ("Never silently green"). With the stages filtered out and the flag empty,
  the tightening forces the election false; `anchor_validation` then reports its skip outcome.
- Role assignments **never feed back** into `config.anchor_platform` anywhere in this file.

### Hop 4 — The e3297391 fix and why it did not fire

`e3297391` (merge of `24a76328`, "Keep macOS anchor validator stages on the skip-live-suite fast
path") added `PlanBuilder::with_skip_live_suite` / `::with_anchor_platform_macos` and an
include-filter that retains exactly the three `MacosAnchor*` StageIds under `skip_live_suite` when
the election flag is true; wired from `native.rs` at plan construction (`:335`). The unit test
`macos_anchor_validator_stages_follow_the_live_suite_gate` proves the filter — **conditional on
`anchor_platform_macos == true`**, which the `ai_lab_run` rust-engine path never produces. The fix
is correct at its layer; it is starved one hop upstream.

---

## 3) Exact break point and owning layer

**Break point:** MCP layer, `build_orchestrator_args` rust-engine branch
(`crates/rustynet-mcp/src/bin/ai_agent.rs` ~6440-6510). `anchor_platform` is consumed exclusively as
a role assignment; the raw `--anchor-platform macos` flag is never forwarded.

**Owning layer / contract mismatch:** the native orchestrator's *plan-structure* election
(`native.rs:335`, `:261`, `:377-388`) is defined over `config.anchor_platform` (the raw flag), while
the rust-engine invocation contract delivers the same intent as a *role assignment*
(`config.node_assignments`). Two representations of one intent, only one of which crosses the
boundary. The bash-era flag contract and the rust-era node-assignment contract were never
reconciled at the election site.

---

## 4) Fix direction (description only; not applied)

**Recommended — make `native.rs` the single source of truth (assignment-derived election):**

- Where: `crates/rustynet-cli/src/vm_lab/orchestrator/native.rs`, after `ctx.assignments` is fully
  populated (post `:240-250`), before first use.
- What: derive a local
  `anchor_platform_macos_elected = (config.anchor_platform.as_deref() == Some("macos"))
  || ctx.assignments contains an Anchor-role alias whose inventory entry has platform == macos`.
  The inventory is already in scope (the augment call at `:240-250` takes `&inventory`).
- Use that local at all three election sites: plan construction (`:335`), the preliminary election
  (`:261`), and the post-plan tightening (`:377-388`).
- Why this shape: zero MCP/CLI change; honors both invocation styles (raw flag and `--node`
  synthesis); cannot regress the bash-retired path (flag arm is simply the OR's first term); and it
  removes the two-representations trap rather than patching one caller of it.

**Alternative — forward `--anchor-platform` from the MCP rust-engine path — evaluated and rejected
as-is:** emitting the flag in `build_orchestrator_args`'s rust-engine branch would reach
`augment_assignments_from_platform_selectors` (`native.rs:963+`), which would then try to assign a
*second* macOS entry (the macOS guest is already assigned via `--node`) and hard-error on
single-macOS fleets ("--anchor-platform=macos: no unassigned inventory entry found"). Making it work
additionally requires an idempotency guard in augment (skip a selector when an Anchor-role
assignment already exists on that platform) — more moving parts for the same outcome.

---

## 5) Blast radius on the other `ai_lab_run` role selectors

- **`exit_platform`, `relay_platform`, `admin_platform`, `blind_exit_platform`: NOT affected.**
  Their only `native.rs` consumer is the augment call (`:245-249`), which is pure assignment
  augmentation — a function the rust engine's `--node` synthesis fully replaces. Their mac/win role
  cells therefore still run live when elected through `ai_lab_run`.
- **`anchor_platform` is unique** in having a second, plan-structure consumer (the MAC-D3
  validator-stage election). That dual consumer is exactly why only this selector broke.
- **Same latent pattern, unconfirmed:** `role_switch_platform` and `macos_promote_exit` also exist
  only as raw flags on the retired bash arm (the run manifest records `role_switch_platform: ""`).
  Whether any plan-structure logic reads them the way MAC-D3 reads `anchor_platform` was **not**
  verified in this investigation — flagged as a follow-up check, not as a confirmed defect.

---

## 6) Verification anchors

- Repro of the loss: any `ai_lab_run` call with `anchor_platform: "macos"` +
  `skip_linux_live_suite: true` on the default engine; inspect the run's
  `orchestration/stage_manifest.json` — `anchor_platform` will read `""` while `nodes.tsv` shows the
  anchor role assigned.
- Post-fix acceptance: same invocation must yield the three `MacosAnchor*` stages `enabled: true`
  in `stage_manifest.json`, with `macos_anchor_validators_elected` true, and the existing unit test
  `macos_anchor_validator_stages_follow_the_live_suite_gate` still green (its condition is a strict
  subset of the proposed OR).
- Run-matrix discipline: after the fix lands, take the pass/fail claim from the stages' own report
  artifacts in the run's report directory, never from the ledger column alone (AGENTS.md §12.3).
