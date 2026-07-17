# Security Stage Backlog Status Check — 2026-07-04

Status: **active reference**. Read-only status-check ledger, not a design doc.
Written after a 141-commit gap (33k+ insertions) landed on `main` between the
prior security-stage session's last commit (`0e5aec0`) and current HEAD
(`8138983`), to answer one question: **given everything that landed in the
interim, what from the prior session's backlog is still actually open?**

Method: a 12-agent parallel verification pass (4 stage-integrity checks + 6
ledger surveys + 2 GUI-code checks), cross-checked against direct reads of
the primary ledgers and direct `git`/`grep` on the current working tree. Two
of the ledger-survey agents returned degenerate placeholder output (a
`StructuredOutput` retry-cap failure) and were re-done by direct read.  All
findings below are evidence-cited (file:line); none are taken on a report's
word.

## 1) Confirmed intact — no action needed

The prior session landed 6 items (2 Tier-0 + 4 Tier-1-priority-order items,
see `LiveLabSecurityTestCoverage_2026-06-22.md` §"Priority order"): `RSA-0009`
/ `DD-03` (Tier 0), and `RT-2` / `GM-1` / `ENR-1` / `TOCTOU-1` / `DOS-1`
(Tier 1, priorities 1–5). All six were re-verified end-to-end against current
`main` (`8138983`) and are **intact, unbroken, and correctly wired** — no
regression from the 141 intervening commits:

| Stage | vm_lab/mod.rs (evaluator+runner+dispatch+vec) | Daemon audit module | CSV | lab-monitor GUI | MCP `explain_stage` |
|---|---|---|---|---|---|
| `validate_linux_blind_exit_reversal_denied` (RT-2) | ✅ | ✅ `blind_exit_reversal_audit.rs` | ✅ | ✅ | ✅ |
| `validate_linux_gossip_revoked_readmit` (GM-1/RSA-0034) | ✅ | ✅ `gossip_revoked_readmit_audit.rs` | ✅ | ✅ | ✅ |
| `validate_linux_enrollment_replay` (ENR-1/TOCTOU-1) | ✅ | ✅ `enrollment_replay_audit.rs` | ✅ | ✅ | ✅ |
| `validate_linux_hello_limiter_flood` (DOS-1/RSA-0037) | ✅ | ✅ `hello_limiter_audit.rs` (rustynet-relay) | ✅ | ✅ | ✅ |

Representative evidence (full citations in the workflow transcript,
`wf_2c99cea1-b90`):
- `crates/rustynet-cli/src/vm_lab/mod.rs`: each stage's evaluator (e.g.
  `evaluate_blind_exit_reversal_report` ~L18119, `evaluate_gossip_revoked_readmit_report`
  ~L18268, `evaluate_enrollment_replay_report` ~L18328,
  `evaluate_hello_limiter_flood_report` ~L18384), stage-runner, and
  `dispatch_stage`/`stage_outcome` call are all present, and each stage's
  outcome variable is still an element of the `vec![...]` returned by the
  per-alias Linux daemon-validator runner (now `run_linux_orchestration_stages_with_options`
  → `run_linux_daemon_validators_for_aliases`, ~L22348, invoked from the main
  `vm-lab-orchestrate-live-lab` path at ~L8188/L8267).
- Each stage also now has macOS/Windows stage-runner variants reusing the
  same evaluator — cross-platform coverage beyond the original Linux-only
  ask (added by other work in the 141-commit gap, not by us; not a
  regression, a bonus).
- CSV wiring migrated from the original hardcoded `set_special_stage_values`
  match-arm design to a **registry-backed** design
  (`crates/rustynet-cli/src/live_lab_stage_registry.rs`, `StageSpec.special`
  field) as part of the `LiveLabStageContractPlan_2026-07-03.md` program (§4
  below) — functionally equivalent, all 4 stages' `special` column mappings
  present and drift-gate-tested.
- `crates/rustynet-lab-monitor/src/data/run_matrix.rs`: the `LINUX_ONEOFF_COLUMNS`
  constant we originally wired into **no longer exists** — it was refactored
  into header-driven discovery (`is_oneoff_check_column`, ~L412) by an
  unrelated commit. Cosmetic drift only; all 4 columns still render correctly
  (each is a `{os}_`-prefixed, non-`_stage_`, non-metadata column, which is
  exactly what `is_oneoff_check_column` selects for).
- `crates/rustynet-mcp/src/bin/lab_state.rs`: all 4 `StageInfo` entries
  present with correct aliases (`rt-2`, `gm-1`, `enr-1`/`toctou-1`, `dos-1`).

**No follow-up needed here.** This section exists purely as the
"already-done, re-verified, don't redo it" record.

## 2) Genuinely still open — the 2 lab-monitor GUI items

Neither was touched by any of the 141 intervening commits. Both re-confirmed
present in the working tree as of 2026-07-04.

### 2.1 No `StageCategory` / dedicated SECURITY section exists

`crates/rustynet-lab-monitor/` has no `StageCategory` type anywhere (zero
grep hits). Grouping is still purely per-OS:
- `data/run_matrix.rs`: private `ScopeGroup` enum (~L346) — exactly 4
  variants (`Linux`/`Macos`/`Windows`/`CrossOs`), used by `scope_group_of()`
  (~L353) to bucket CSV columns. `discover_oneoff_columns()` (~L846)
  explicitly folds each OS's one-off security columns into that OS's own
  bucket (comment ~L855-856: "every OS's one-off security columns, plus
  cross_os_* as a shared bucket").
- `ui/stage_matrix_panel.rs`: renders exactly 4 hardcoded sections — "LINUX"
  (~L76), "MACOS" (~L85), "WINDOWS" (~L93), plus cross_os. Doc comment ~L13:
  "one column per OS." No "SECURITY" section.
- `app.rs::planned_stage_groups()` (~L898) returns 3 groups: "PRE",
  "BOOTSTRAP", "LIVE LAB" — "security" appears only in doc-comments
  describing one-off audit stage lists (~L2314, ~L2363), not as a rendered
  category.

**Conclusion**: security-audit stages are a recognized *subset* internally
(`is_oneoff_check_column`) but are never surfaced as their own
category/section in the GUI — always folded into their owning OS's bucket.

### 2.2 `disabled_stages` GUI toggle still lies about its effect

The mismatch is real, unfixed, and **the code itself already documents it**:
- `app.rs::toggle_selected_stage` (~L1607-1635): any stage the current
  config makes selectable can be pushed into `disabled_stages` (a generic
  `Vec<String>`), no special-casing.
- `app.rs::handle_start` (~L1714-1727) computes
  `unsupported_disabled` (every `disabled_stages` entry except the literal
  string `"linux_live_suite"`) and logs: `"stage toggles enforced by CLI
  today: linux_live_suite only; unsupported disabled count: {}"` — i.e. the
  author already knew and flagged it, but shipped it anyway.
- `control/launcher.rs::build_loop_args` (~L13-63, called from
  `spawn_orchestrator` ~L171) never reads `config.disabled_stages` at all —
  only `config.skip_linux_live_suite` (~L55-57).
- `config.rs` (~L39,74,78,116-125,177) keeps `disabled_stages` and
  `skip_linux_live_suite` in sync **one-directionally, only for the
  synthetic `"linux_live_suite"` pseudo-stage name** — every other toggled
  entry (`preflight`, `validate_macos_mesh_join`, `traffic_test_matrix`, …)
  is persisted to disk but never read by the launcher or
  `scripts/loop/opencode_loop.sh` (which only recognizes
  `skip_linux_live_suite`, per its own grep hits at L116/L368/L765/L768).
- No `--skip-stage`/`--disable-stage`-style per-stage CLI flag exists
  anywhere in `rustynet-cli`.

This exact gap was already called out once before and left open:
`LiveLabSecurityTestCoverage_2026-06-22.md` §9 — *"Dead config found, not
wired to either MCP server: `disabled_stages` … has no effect on
`deepseek_lab_run` or `start_live_lab_run` — the control looks functional in
the GUI but does nothing."* A narrower adjacent issue (unknown/stale stage
names not pruned) **was** fixed as part of the stage-contract program
(`prune_unknown_disabled_stages`, commit `d91dac3`, tracked as Finding 9 in
`LiveLabStageContractPlan_2026-07-03.md`, marked DONE) — but that only
prunes *invalid* names; it does not make *valid* toggled-off stages actually
get skipped. The core mismatch remains.

**Two legitimate fix shapes, not yet decided between:**
1. Wire `disabled_stages` for real — thread it through
   `build_loop_args`/`opencode_loop.sh`/the orchestrator as an actual
   per-stage skip mechanism.
2. Remove the illusion — restrict the stage-grid toggle to only the one
   stage name that's real (`linux_live_suite`), or grey out/disable toggling
   for every other stage until (1) is done.

## 3) Ledger sync needed — `LiveLabSecurityTestCoverage_2026-06-22.md` is stale

The doc's own "Priority order — build sequence (reprioritized 2026-07-01)"
section (top of file, §"Tier 0" and §"Tier 1" table) still lists the 6 items
in §1 above as if unbuilt. They are done (§1). The doc needs:
- Tier 0 items #1 (`RSA-0009`) and #2 (`DD-03`) marked done-and-live-proven
  (or done-code-verified-if-live-proof-is-separately-tracked — check the
  run-matrix for an actual live pass row before claiming live-proven).
- Tier 1 priority rows 1–5 (`GM-1`, `ENR-1`, `TOCTOU-1`, `DOS-1`, `RT-2`)
  marked done.
- The "build next" pointer moved to Tier 1 priority 6 (`RR-01/02/03`).

This is a quick, mechanical fix — flagged as task #14 in the session that
produced this doc. Doing it prevents a future session from re-discovering
and re-verifying the same 6 items from scratch the way this session had to.

## 4) Remaining backlog — Tier 1 priorities 6–16 + Tier 2 (confirmed zero code)

Cross-checked two ways: (a) `LiveLabSecurityTestCoverage_2026-06-22.md`'s own
Tier 1/Tier 2 tables, (b) an independent `grep`-based audit inside
`ParallelAgentWorkPlan_2026-07-01.md`'s Job 1/3/4 partition (that document
exists specifically to *not duplicate* in-flight work, so its own status
check is a second, independent confirmation). Both agree: **none of the
following have any code**, despite 141 commits landing in the interim on
other tracks (mostly the FIS intelligent-systems program and cross-OS role
transitions — see §5/§6).

| Priority | ID | Stage | Severity note |
|---|---|---|---|
| 6 | RR-01/02/03 | `validate_linux_replay_persistence` (+traversal/enrollment variants) | Anti-replay watermark is in-memory only (RSA-0029) — doesn't survive daemon reboot |
| 7 | FCF-1/2/3 | `validate_linux_crash_midapply_failclosed` / `_corrupt_state_failclosed` / `_keystore_unavailable_failclosed` | **Flagged in `ParallelAgentWorkPlan_2026-07-01.md` §3.1 as the single most severe open item in the whole plan** — daemon fail-closed behavior on `kill -9` mid-signed-state-write is unverified |
| 8 | RPT-01 / HP-3 | Relay live packet-forwarding proof | No stage on any OS has EVER proven a real frame was forwarded — today's "relay" coverage is lifecycle-only (start/healthz/stop). Tracked since `MasterWorkPlan_2026-03-22.md`; "the single biggest looks-done-but-isn't gap in the whole matrix" |
| 9 | S3-10 | `validate_macos_codesign` (+Windows Authenticode deploy-time) | Today's binary-integrity checks are CI-gate-only, not live-lab-deploy-time |
| 10 | RSA-0063 | `validate_macos_bootstrap_privesc_residue` | Code fix landed 2026-06-24, but **the live-lab proof stage does not exist** — one of only 2 standing High-severity `SecurityAuditLedger_2026-06-18.md` findings still lacking live verification |
| 11 | KC-04 | Windows key-custody negative path | `validate_key_custody_permissions` no-ops on non-Unix (RSA-0002) — a world-readable key silently passes on Windows |
| 12 | PH-7 | `validate_macos_privileged_helper_allowlist` | Same adversarial argv corpus already proven on Linux, needs a `pfctl` port |
| 13 | KL-2/3/4 | macOS/Windows killswitch-leak parity | Linux has full v4+v6 active-probe+capture; other OSes don't |
| 14 | KC-07 | macOS/Windows secrets-not-in-logs parity | Linux-only today. (RSA-0080 **applied 2026-07-17**; the Linux secrets-hygiene gate is **GREEN** and no longer blocks this item.) |
| 15 | CNT-1 | `validate_linux_upnp_ssrf` | Confirmed-present SSDP LOCATION/controlURL SSRF (RSA-0035), zero live coverage |
| 16 | PH-2/3 | Privileged-helper live socket fuzz + cross-UID rejection | Today's helper coverage is argv-only — nothing attacks the live IPC socket itself |

Tier 2 (larger, infra-gated, same zero-code status): HP-3 (see row 8 above,
duplicate entry point), nas/llm M5 live evidence chain, cross-network
NAT-profile substrate (X1–X3), real cross-OS role-*switch* (as opposed to
role-*transition*, which Job 2 below did land).

## 5) Adjacent finding — the new stage-contract program has 2 gaps that touch security stages

`LiveLabStageContractPlan_2026-07-03.md` (a large, mostly-DONE observability
program — registry/manifest/upsert/terminal-state-barrier/timer-budgets/
header-math/area-string-demotion/disabled_stages-pruning, see that doc for
the full status) has two open items specifically relevant to the security
stage family in §1/§4:

1. **Finding 5 (coverage-as-code) gate enforcement is still open.** v1
   (report-only, cross-referencing the registry's `proves` field against
   run-matrix evidence) is DONE (`bf3640e`) — all six audit-control families
   are live-proven on all 3 OSes as of 2026-07-03. But *enforcing* it (i.e.
   actually blocking/flagging a run when a security-control family lacks
   coverage, with reviewed exceptions) is explicitly still open. This is the
   mechanism that would make future backlog items in §4 impossible to skip
   silently.
2. **Deliberate known gap**: `conditional_dispatch`/barrier-exempt stages —
   which the doc's own text says includes "per-OS audit families, standalone
   linux validators" (i.e. stages like the ones in §1/§4) — are exempt from
   the new conclusion barrier. A missing outcome for one of these stages is
   not currently flagged as abnormal termination.

Neither blocks new stage work; both are worth keeping in mind if/when the
§4 backlog gets built, since new security stages will inherit these two
gaps until Finding 5's enforcement half and the barrier-exemption are
revisited.

## 6) Related but separate — near-term hardening targets (not security-audit stages, but adjacent)

`FocusedLiveLabRoleGapAnalysis_2026-07-02.md` (static-analysis-only, no live
lab run) covers three targets that are part of the parity mandate, not the
security-stage backlog, but worth tracking alongside it:

- **Linux `blind_exit`**: dataplane code exists and is unit-tested
  (mesh-CIDR-scoped forward, NAT refusal, posture-retention, hard-lock
  rollback). Still needed: an actual live stage that starts a real Linux
  guest in blind_exit mode, captures the real `nft list ruleset`, and adds
  active positive/negative probes (mesh-source allowed; non-mesh/local-origin/
  DNS-leak/generic-forward blocked; NAT absent). Currently only
  reversal/immutability is proven (§1's RT-2), not the live dataplane
  posture itself. Secondary: a stale `PrivilegedCommandClient` framing
  mismatch in older helper tests can mask allowlist regressions.
- **macOS `admin`**: narrow local-mint proof exists and is live-proven.
  Still needed: a `validate_macos_admin_peer_ingest` stage where a real peer
  (e.g. Linux) applies the macOS-issued bundle through the production
  verify-before-apply path, plus negative cases (stale generation, forged
  signature, unauthorized escalation, revoked-admin/wrong-verifier) and a
  secrets-in-logs check.
- **Windows `anchor.bundle_pull`**: daemon + installer + orchestration all
  exist and are fail-loud. Currently blocked pre-security-check by a
  transport failure (`exec request failed on channel 0`, exit 255) on
  `windows-utm-1` — doc's hypothesis is unreliable SSH for the installer on
  that guest; recommends forcing local-UTM result-file execution instead.

**Currency caveat**: `live_lab_run_matrix.csv` shows rows through
2026-07-04 including `live-lab-windows-anchor-reverify-1` and
`live-lab-macos-admin-reverify-1`, suggesting lab work on exactly these two
cells has continued since this doc was written (2026-07-02) — but that
doc was not updated to reflect it, so treat its "still needed" list as
possibly-partially-stale; re-verify against the run matrix before
re-deriving work from it.

`MacWinStageParityPlan_2026-07-02.md` (separate track: closing the raw
column-count gap, Linux 36 vs mac/Windows 23 columns each) has all 10 of its
own checklist items unchecked — nothing in it is done as of this check.

## 7) Suggested priority order if/when this backlog is picked back up

1. §3 (ledger sync) — 15 minutes, prevents re-discovery cost for the next
   session.
2. §2.2 (`disabled_stages` truthfulness) — small, high user-trust payoff,
   two options already scoped above; just needs a decision between them.
3. §4 row 7 (FCF-1/2/3) — highest standing severity of anything with zero
   code today.
4. §4 row 8 (RPT-01/HP-3) — highest-visibility "looks done but isn't" gap;
   unblocks the relay-forwarding story across the whole parity matrix, not
   just security.
5. §4 row 10 (RSA-0063 live validator) — one of only 2 standing High
   findings in the whole security audit ledger without live proof; likely
   small effort since the code fix already exists (mirrors the ENR-1/TOCTOU-1
   pattern from §1: promote an already-fixed bug to live evidence).
6. §2.1 (StageCategory/SECURITY GUI section) — pure observability, lowest
   urgency, but cheap once the stage list stabilizes.
7. Everything else in §4 (rows 6, 9, 11–16) and §6, roughly in the order
   listed, unless a specific incident or audit re-prioritizes.

This ordering is a suggestion, not a decision — the actual next session
should re-run the equivalent of §1's verification pass first (git may have
moved again) before trusting this list at face value.
