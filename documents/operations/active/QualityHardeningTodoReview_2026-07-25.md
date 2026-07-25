# Adversarial review of `QualityHardeningTodo_2026-07-25.md` — 2026-07-25

**Reviewer:** WS-D. **Method:** all items fanned across three independent opus reviews,
each grounded in code, then the load-bearing claims re-verified by hand. Read-only; no
lab/`ops`/SSH commands run. Tree: `main` @ `f9388393`.

**Why:** the register's own norm — *"a finding is not a finding until someone
independently reproduced it"* — had not been applied to the register itself. Applying it
found **one false retraction, three refuted claims, four misattributions, and four
findings the register does not record.** Every item still describes a real defect; the
prose around them is what needs fixing.

## 0. Verdict at a glance

| Item | Verdict | The correction that matters |
|---|---|---|
| QH-01 | **VERIFIED** | Mechanism exact. But its fix framing (ordering) is insufficient — see §1. Cites a validator that doesn't exist. |
| QH-02 | PARTIALLY-CORRECT | Mechanism *stronger* than claimed; cited mutation impossible; **the two exemplar tests are swapped**; acceptance vacuous. |
| QH-03 | **REFUTED for the script it names** | Provisioning script is well-guarded (7 `exit N`). The fail-open scripts are `HOST_RECOVER_VMS` + `HOST_DISK_STATUS`. |
| QH-04 | PARTIALLY-CORRECT | **"Unrecoverable" is false** (self-heals). But genuinely **product + release-blocking**. Citation trail broken. |
| QH-05 | **VERIFIED** | Worse than stated: both false comments are **live on `main`**, not history. Unenforceable as written (303 violations, no marker). |
| QH-06 | **VERIFIED** | Reproduced: clippy passes clean, no exclusions. The stale guidance lives in 6 places — including the charter I was following. |
| QH-07 | **CONTAINS A FALSE RETRACTION** | The retracted "43 false-green rows" claim is **CORRECT**. Root cause is a **ledger-code defect**, not prose. |
| QH-08 | PARTIALLY-CORRECT | Its named "hard failure mode" (setup-manifest hash) is **dead code on the default `--node` path**. |
| QH-09 | PARTIALLY-CORRECT | Diagnosis **inverted** (disclosure is prepended; tail-keeping is deliberate + documented). Real defects elsewhere. |
| QH-10 | PARTIALLY-CORRECT | Fix already implemented on the readiness path. macOS currency **contested by `CLAUDE.md:421`** — QH-10 violates QH-06. |
| QH-11 | **VERIFIED, understated** | Bigger: **121 ledger rows cite evidence in `/tmp`**. Previously found 5 days earlier and lost. |
| QH-12 | **REFUTED as written** | Named helper **doesn't exist**; 1 caller not 2; **9** copies not 8. Written against a different tree. |
| QH-13 | **VERIFIED → upgrade** | INFERRED → **VERIFIED** on vendor docs. Severity medium → **high**. Its own premise understates it. |

## 1. The most urgent finding: QH-07's retraction is false (reclassify to HIGH)
The register "retracts" a claim of 43 false-green `pass` rows, stating the true
distribution is 97 skip / 9 not_run / 1 fail with no `pass`. **Verified by hand — the
retraction is wrong and the original claim was right:**
- Quote-aware parse (`csv.reader`, column located by header name, index 46):
  **`pass: 43`, `skip: 22`, `fail: 34`, `not_run: 9`** across 108 data rows.
- The register's numbers are reproducible **only by a naive comma split**:
  `awk -F, '{print $47}'` → `98 skip / 9 not_run / 1 fail` (vs its 97/9/1 — a
  one-row-older snapshot). Every row carries a quoted `notes` field (index 16)
  containing commas, which shifts the whole stage block.
- **The false-green is real.** `live_two_hop_validation` lifetime record:
  **116 fail / 263 skip / 0 pass — it has never passed.** `traffic_test_matrix`:
  260 pass. The alias table collapses **both** into one column —
  `live_lab_run_matrix.rs:3744` `"traffic_test_matrix" => Some("two_hop")` alongside
  `:3770` `"live_two_hop_validation" => Some("two_hop")` (and `:3747`).
  So `linux_stage_two_hop = pass` means *"the mesh pinged"* while the actual
  chained-exit proof was skipped.

**Why this outranks everything else in the register:** `CLAUDE.md:418` / `AGENTS.md:418`
instruct **every agent** to "verify the appended row in
`live_lab_node_run_matrix.csv`" as their acceptance criterion — pointing them at a
column that reads `pass` on 43 rows for a stage that has never passed. The register's own
diagnosis (*"the weakness is in how criteria are written, not in the ledger code"*) is
**wrong**: NO-VERDICT logic correctly handles *absence*, but here the cell says `pass`.
This is a code defect.
**Fix:** (a) strike the retraction, restore the finding with the cross-ledger proof;
(b) split `traffic_test_matrix` out of the `two_hop` column, or fail the append when two
distinct stages map to one column. Note the repo already knows this class —
`live_lab_run_matrix.rs:430-433` documents the identical bash-era "52 passes" false-green
and fixed it by splitting *ledgers*, leaving the *stage aliasing* in place.

## 2. QH-06 — verified, and it was polluting my own work
Reproduced on the pinned toolchain (`cargo 1.88.0`):
`cargo clippy --workspace --all-targets --all-features -- -D warnings` → **exit 0, zero
diagnostics, `rustynet-mcp` included**. `-p rustynet-mcp` alone: clean. Under Homebrew
`cargo 1.97.0` the same crate emits 2 lints that don't exist on 0.1.88 → **the "known
red" is a toolchain artifact.** And **CI never excludes it**
(`.github/workflows/cross-platform-ci.yml:27,63` run the bare workspace clippy; the only
exclusion is `rustynet-lab-monitor`, which is excluded in the root `Cargo.toml`).
**Strike the stale guidance in 6 places:** `orchestrator_charter.md:87` and `:267`
(self-defeating — the same bullet states the pin *then* says to exclude anyway),
`BashRetirementPlan_2026-07-24.md:70`, `LinuxMtuPrivilegedHelperAllowlistGap_2026-07-21.md:158`,
`AnchorBundlePullAttestationSecurityReview_2026-07-20.md:278`,
`ParallelAgentWorkPlan_2026-07-01.md:266`. Also: `DocCodeDiscrepancyAudit_2026-07-18.md`
still marks DA-17 (backend-boundary gate) "Confirmed, worse" **5 days after `1d4d3437`
fixed it** — the gate passes now (verified). `CLAUDE.md:421` is the working exemplar of
the convention this item wants (dated re-verification + probe table + cost note).
**Self-correction:** I followed `--exclude rustynet-mcp` throughout this session's gates.
It is unnecessary and was masking real regressions in the crate that fronts every MCP
tool surface.

## 3. Findings the register does not record
- **`--image` is a live quote-breakout** on the provision path, needing **no**
  `--authorized-key` and no placeholder trick. `ensure_provision_image_name`
  (`vm_lab/mod.rs:6323`) is a deny-list rejecting only empty/`/`/`..`/control chars. A
  compiled copy accepts: `x'; id; '`, `a'$(id)'`, ``debian`id`.qcow2``, `deb$USER.qcow2`,
  Cyrillic-е homoglyph, 500 chars, `x;id`, `x|id`, `x&id`, `-leading-dash.qcow2`. Renders
  `IMAGE='x'; id; ''`. **Also: no length bound** (unlike name's 1..=60).
- **`--pool` is unvalidated and reaches TWO sinks** — `POOL='__POOL__'` (`:6564`,
  direct breakout) **and** an SSH-argv sink (`findmnt --target <pool>`, `:6459`). This
  **falsifies QH-13's premise** ("a pool value validated for a single-quoted-script
  context" — it isn't validated at all there).
- **A second exact-set-equality site** for QH-04 at `daemon.rs:6208-6230`
  (`sync_traversal_runtime_state`) — any atomicity fix must cover both.
- **A latent panic:** `ops_live_lab_failure_digest.rs:436` byte-slices a `&str`
  (`text[..max_len-3]`) whose input preserves non-ASCII → a multi-byte char straddling
  the cut panics failure-digest generation for a whole run.

## 4. Claims that must not be inherited as written
1. QH-01/QH-12: **`ensure_single_quoted_script_value` does not exist.** The real helper is
   `ensure_orchestrator_arg_safe` (`mod.rs:5067`), **1** caller (`:5834`).
2. QH-12: **9** hand-rolled `contains('\'')` sites, not 8 (`:5262, 5541, 5545, 5719, 5826,
   5830, 5851, 5865, 6511`); the 10th match is the helper's own body. And the file has
   **four** idioms — including `shell_quote` (`:37993`, ~20 sites), the *correct* escaper.
   Deduplicating toward the reject rule would consolidate on the weaker answer.
3. QH-02: no `pool` validation call exists to remove; the "good pattern" and "mirror"
   tests are **swapped** (`provision_image_must_be_a_bare_filename` `:41756` is the weak
   mirror; `provision_guest_name_rejects_anything_not_obviously_safe` `:41729` is the
   attack-class one — and neither has a homoglyph or leading-`.` case);
   "fails on revert" is unfalsifiable — say *which* deletion turns it red.
4. QH-03: "any mid-script failure can be reported as success" is false for provisioning
   (7 `exit N` guards; `run_guest_script` checks `status.success()` at `:4585`, so the
   contract is conjunctive). True of `HOST_RECOVER_VMS_SCRIPT` (`:5087`) and
   `HOST_DISK_STATUS_SCRIPT` (`:5212`) — zero non-zero exits, unconditional sentinel.
   Also "audit every `const *_SCRIPT`" is the wrong predicate (misses
   `recover_guest_network.rs:260/280/296`; sweeps in 6 shell-free path consts).
5. QH-04: **"permanently restricts itself / unrecoverable" is false** — reconcile clears
   `restriction_mode` and `reconcile_failures` on the next success **even from Permanent**
   (`daemon.rs:9067/9069`), and `StateRefresh` IPC is exempt. Say *"stays restricted until
   the matching half arrives or an operator issues `state refresh`"*. The current wording
   drives a heavier fix than needed. **I propagated this error myself** in loop-journal
   notes #435/#436 — corrected there.
6. QH-04: the citation trail is broken — `NodeEngineFlipDispositions_2026-07-24.md` (D1)
   contains **none** of the claimed atomicity analysis, scoping, or fix shapes; nor does
   `TraversalSelfSustenancePlan`. The real source is an **uncommitted** comment
   (`live_linux_two_hop_test.rs:335`) whose own citation is wrong.
7. QH-05: reads as history, but **both false comments are live on `main`**
   (`mod.rs:6558-6561` and `:4978-4980`); the fixes are on `claude/host-observability`,
   not an ancestor of `main`.
8. QH-07: the retraction (§1). 9. QH-08: the setup-manifest hash is **dead on the default
   path** — only `vm_lab/mod.rs` is hashed, `orchestrator/**` is not, and the node engine
   writes the sentinel `rust-native-no-setup-manifest`. 10. QH-10: the macOS false-negative
   is **contested** — `CLAUDE.md:421` re-verified it as NOT blocking on 2026-07-17; the
   Windows/Defender half is single-sourced by QH-10 itself. 11. QH-13: severity **high**,
   confidence **VERIFIED** (vendor-documented; reproduction not required).
12. `README.md:14` says "13 cross-cutting defects"; the register has **15**.

## 5. Corrected priority order
1. **QH-07** — the only item whose *evidence* is defective, and every agent is instructed
   to trust the broken column. Ledger-code fix.
2. **QH-13** (upgraded to high) — fail-**open**, live on `main`, MCP-reachable/agent-drivable,
   and **silent** (QH-03's missing `-e`). `run_host_cmd` is a single chokepoint → validate
   inside it, not at 8 call sites. Ranked above QH-04 because that one is fail-*closed*
   (availability, not integrity).
3. **QH-01** (in progress, WS-D) — with `pool`+`image` now in scope; also closes QH-02's
   class for that function via the real-call-path `dry_run` test.
4. **QH-04** — release-blocking product defect. Best shape: **staged-pair grace** (change
   *when* the existing check fires, not what it enforces), scoped strictly to the
   transitional case; hold the combined artifact as the durable fix. Note the production
   trigger the register misses: `assignment-refresh`'s assignment-TTL short-circuit
   (`main.rs:9520-9528`) installs traversal *always* but re-mints the assignment only near
   expiry → a tens-of-seconds-to-~2-minute window against a **5-second** tolerance
   (`DEFAULT_MAX_RECONCILE_FAILURES=5` × 1 s). Plus independent-URL pulls, plus
   **membership revocation** as a third trigger.
5. **QH-06** — highest leverage per hour; 6 deletions + 1 ledger correction.
6. **QH-11** (→ medium) — one `report_dir` validation at append time closes it; 121 rows
   currently cite `/tmp`. Previously found in `RepoReview_2026-07-20.md:152` and lost.
7. **QH-09** — mostly one-line `truncate_output` → `truncate_tail` swaps (the correct
   helper already exists and its doc names this case), incl. the **LLM triage pipeline**
   and the `cargo check` path its own comment calls "GROUND TRUTH". Split out the latent
   panic (§3) as its own item.
8. **QH-05** — real and current, but actionable only narrowed: a `SAFETY-INVARIANT:`
   marker with a **`verified-by` existence check** (`cargo test -- --list`), scoped first
   to `const *_SCRIPT` doc comments. Land alongside QH-01, which rewrites those sites.
9. **QH-08** — do what the code wants instead of the stated fix: wire the existing
   `--require-clean-tree` refusal into the default `--node` path (`--allow-dirty` to
   override), and hoist the two duplicated 6-entry exclusion lists into one constant (the
   bash path `live_linux_lab_orchestrator.sh:5059` is already drifted).
10. **QH-10** — effectively resolved; reduce to two checkable actions: give
    `lab_state.rs:3418`'s duplicate probe the SSH-auth override `mod.rs:31137` has, and
    date-stamp the macOS claim per QH-06.

## 6. Process observations
- **The register's own norm works.** Applying it caught a false retraction, an inverted
  diagnosis, an unsourced citation, a mis-stated premise, and a stale-belief item that
  violates the very item two entries above it (QH-10 vs QH-06). Keep the norm; apply it
  to the register on write, not only to code.
- **Every item should name the tree/commit it was verified against.** Several describe
  code on `claude/host-observability` or in uncommitted worktrees as if it were `main` —
  which is what produced QH-12's wrong counts and QH-05's "history" framing.
- **Confidence labels need splitting** where mechanism and example diverge (QH-02, QH-03,
  QH-10): VERIFIED-mechanism / REFUTED-example is more useful than one word.
- Housekeeping: an untracked file literally named `-` sits at the repo root.
