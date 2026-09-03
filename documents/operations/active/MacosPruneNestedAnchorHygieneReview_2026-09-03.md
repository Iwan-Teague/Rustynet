# Adversarial Review — §Q5 Guarded Nested-Anchor Prune (`MacosPruneNestedAnchorHygiene_2026-09-03`)

- **Date:** 2026-09-03
- **Subject:** Adversarial, docs-only review of the guarded-fix proposal in
  `MacosPruneNestedAnchorHygiene_2026-09-03.md` §Q5 (macOS pf owned-anchor prune:
  sweep stale `com.apple/rustynet_g{N}` anchors without ever flushing the
  current-generation DNS floor).
- **Bar applied:** if the current-generation floor is not PROVEN never flushed
  by the proposal as amended, the verdict is NOT-READY.
- **Scope discipline:** no code was modified; no lab was run. Every claim below
  is cited to `file:line` verified by direct read of the worktree at
  `ai-edit/edit-1788442640955-20863-0`.

## Verdict: READY-WITH-AMENDMENTS (A1–A7)

The core mechanism survives adversarial review: with the proposed two-name
guard (skip the live handle AND the target name), the current-generation floor
is provably never flushed on every path that reaches the prune, because
`self.generation` is the just-rotated target by the time the prune runs and
`self.anchor_name` holds that same target's name. But the proposal contains
**two factual errors** (the `live_anchor` comment's semantics, §A1; the
allowlist arm's admission predicate, §A3), **one test-plan defect** (§A2), and
several under-specified edges that must be stated in the proposal before
implementation (§A4–A7). None block the design; all are documentation-level
amendments to §Q5 itself.

---

## 1. Current-floor safety — PROVEN (with corrected reasoning)

### 1.1 The generation/anchor state at prune time

Production path (sole caller: `phase10.rs:7209-7219`; the dispatcher site at
`phase10.rs:6651-6656` routes role transitions to the same stage, and the
DryRun system's prune at `phase10.rs:1026-1028` is a step recorder only):

1. `apply_dataplane_generation` computes
   `target_generation = self.generation.saturating_add(1)` (`phase10.rs:7115`)
   and commits it with `set_generation(target)` (`phase10.rs:7121`) **before**
   any firewall work.
2. macOS `set_generation` is generation-only — it does not touch
   `anchor_name` (`phase10.rs:4796-4798`).
3. `apply_firewall_killswitch` runs at `phase10.rs:7149`. On macOS it is
   exactly `allow_egress_interface = false;` + `self.apply_pf_rules(false)`
   (`phase10.rs:4960-4963`). Inside `apply_pf_rules`,
   `next_anchor = self.current_anchor_name()` resolves to
   `com.apple/rustynet_g{self.generation}` (`phase10.rs:3880-3885` —
   generation is already the target per step 1), the target anchor is loaded,
   and `self.anchor_name = Some(next_anchor)` is recorded
   (`phase10.rs:4064`). A failure here calls `force_fail_closed` and returns
   (`phase10.rs:7149`), so **the prune is never reached with a half-applied
   generation**.
4. Therefore at the prune call (`phase10.rs:7209`):
   `self.anchor_name == Some(current_anchor_name())` — **live handle and
   target name are the same anchor**, the one carrying the DNS floor
   (`killswitch_spec`, M3 latch at `phase10.rs:3911`;
   `has_live_loopback_dns_pins` fails closed on unreadable state at
   `phase10.rs:3927-3961`).

**Consequence:** a flush loop guarded by "skip if `anchor == self.anchor_name`
OR `anchor == current_anchor_name()`" cannot flush the floor on the production
path. Both comparisons are redundant with each other in-flow — keep both
anyway, mirroring the Linux twin's two-name shape (`phase10.rs:2897-2930`:
`keep_firewall_target = self.firewall_table_name()` from the current
generation plus `keep_firewall_active = self.firewall_table.clone()`).

### 1.2 Refutation of §Q5's `live_anchor` comment (AMENDMENT A1)

§Q5 (iii) writes `let live_anchor = self.anchor_name.clone();` with the
comment *"previous generation, still enforcing"*. That is **wrong at prune
time**: the immediately-previous generation's anchor was already flushed by
the rotate-flush inside `apply_pf_rules`
(`phase10.rs:4031-4042`: when `anchor_name == Some(previous)` and
`previous != next` and not a blind-exit anchor, it runs
`pfctl -a <previous> -F all` via `run_allow_failure` **before** loading the
target). By the time the prune runs there is no "previous generation still
enforcing" — the previous anchor is empty and `anchor_name` names the target.

The two guards collapse to one preserved name in the production flow. This
does not weaken the fix: the double compare is defensive against edge flows
(e.g. a future caller that reaches the prune without a fresh apply) and it is
exactly what the Linux twin does. §Q5 must be amended to say: *preserve-set in
flow = {target}; the live-handle compare is belt-and-braces, retained for
parity with `LinuxCommandSystem::prune_owned_tables`
(`phase10.rs:2897-2930`)*.

### 1.3 Linux twin comparison

- Linux prune (`phase10.rs:2897-2930`): keeps tables equal to the
  target-derived name OR the live handle (plus nat counterparts); deletes
  other owned tables via `run_allow_failure` nft deletes.
- Linux apply (`phase10.rs:3014-3110`): creates the new table, installs rules,
  then deletes the previous table (`phase10.rs:3101-3107`) — i.e. Linux also
  retires the immediately-previous table at apply time, so its prune's
  "active" handle is likewise the target in normal flow.
- Linux test (`phase10.rs:13939-14008`) constructs
  `set_generation(2)` with `firewall_table = Some("rustynet_g1")` — an
  **artificial** active≠target defensive state (comment: "active firewall
  table must not be pruned before handoff"). It proves the guard, not the
  production state.

### 1.4 Sub-conclusion

The current floor is never flushed on any reachable path: prune runs only
after a successful target load with generation already rotated, and both
guard names equal the floor anchor. **Bar met** — modulo the amendments so
the implemented guard matches the proven invariant.

## 2. Preserve-set — current only, in flow

The immediately-previous anchor is emptied by the rotate-flush
(`phase10.rs:4035-4039`) before the target load; nothing re-populates it. The
prune's job is therefore **sweeping anchors left by prior process lifetimes
and prior generations** (restart accumulation: a fresh daemon starts at
generation 0→1 with `anchor_name = None` and nothing enumerates the old
lifetime's `rustynet_g1..gN`), not preserving a live previous generation.
§Q5's framing "preserve current + previous" should read: *preserve current
(in flow == target); sweep all other `com.apple/rustynet_g*` anchors*. The
two-name guard still protects the artificial previous-generation state for
defensive parity, as the Linux twin does.

## 3. blind_exit exclusion — structural, state it (AMENDMENT A4)

The sweep filter `starts_with("com.apple/rustynet_g")` (existing
`owned_anchor_names_from_output`, `phase10.rs:4091-4098`) can never match the
blind-exit anchor: `is_anchor_name_token` admits the namespaces
`com.apple/rustynet_g*`, `com.rustynet/blind_exit`, `com.rustynet/nat`
(`privileged_helper.rs:2090-2106`), so the blind anchor lives under a
different parent and is excluded by the prefix filter alone. The nested query
`pfctl -a com.apple -s Anchors` enumerates only `com.apple` children, so it
cannot surface `com.rustynet/*` at all. Existing guards stay:
`flush_anchor` never flushes a blind anchor and restores the handle
(`phase10.rs:4115-4126`), and the rotate-flush skips blind anchors
(`phase10.rs:4035-4039`). §Q5 should state this exclusion is structural, not
an additional runtime check. A unit test asserting the sweep never contains
`com.rustynet/blind_exit` remains worthwhile (§Q5 (vi) already lists it).

## 4. Privileged boundary — the proposed arm is self-contradictory (AMENDMENT A3)

Verified today's allowlist (`validate_pfctl_args`,
`privileged_helper.rs:3053-3078`, default-deny match, `is_safe_token` over all
argv at `:3054-3058`): arms are `["-E"]`, `["-s","info"]`,
`["-s","Anchors"]`, `["-a",anchor,"-F","all"]`, `["-a",anchor,"-s","rules"]`,
`["-a",anchor,"-s","nat"]`, each anchor-gated. There is **no**
`["-a",…,"-s","Anchors"]` arm, confirming §Q5 (i)'s premise. Exec is argv-only
(`Command::new(binary).args(args)`, `privileged_helper.rs:1822-1823`); `-f`
(load) is banned with the audit-major-#5 rationale
(`privileged_helper.rs:3064-3071`); the negative test
`validate_pfctl_args_permits_nat_anchor_show_and_flush_but_not_load`
(`privileged_helper.rs:6096-6113`) pins the -f rejection.

**The defect:** the proposed arm
`["-a", anchor, "-s", "Anchors"] if is_anchor_name_token(anchor)` can never
admit the nested-enumeration call, because that call's anchor is the bare
parent `"com.apple"` and `is_anchor_name_token("com.apple")` is **false** —
the token test requires the `com.apple/rustynet_g` prefix, `com.rustynet/…`
exact names, or `com.rustynet/nat` (`privileged_helper.rs:2090-2106`).
Proposal steps (i) and (ii) do not compose as written.

Two consistent amendments; §Q5 must pick one and say why:

1. **Constant-match arm** `["-a", "com.apple", "-s", "Anchors"] => Ok(())` —
   no variable at all, the narrowest possible widening of the default-deny
   allowlist; read-only verb (`-s Anchors` lists, never modifies). This keeps
   all pf reads on the privileged-helper boundary.
2. **Reuse the direct reviewed-binary read pattern**: the just-landed
   DNS-floor reader runs `/sbin/pfctl` directly via
   `std::process::Command::new(REVIEWED_PFCTL_PATH)` with
   `REVIEWED_PFCTL_PATH = "/sbin/pfctl"`
   (`macos_dns_failclosed.rs:74`, `:459-468`), and
   `read_pf_dns_block_floor` already issues both `["-s","Anchors"]`
   (`:526`) and `["-a","com.apple","-s","Anchors"]` (`:527`), unioned by
   `merge_rustynet_anchor_names` (`:491-501`). A read-only sweep enumeration
   can use the same pattern — zero privileged-allowlist change, exact
   precedent in the adjacent DNS-floor fix.

**Recommendation:** option 2, to match the just-closed DNS-floor fix and avoid
touching the security-critical allowlist at all; option 1 is acceptable if the
team prefers all pf observation to flow through the helper. Either way the
review's bar (read-only, argv-only, fixed binary path, no `-f`) holds.

## 5. Parsing/filter — guard after enumeration, exact compare (AMENDMENT A6)

- `pfctl -a com.apple -s Anchors` returns lines that include the **current
  floor** (the repo-modeled output in
  `floor_scan_unions_top_level_and_nested_com_apple_anchors`,
  `macos_dns_failclosed.rs:1289-1328`, shows nested lines like
  `com.apple/rustynet_g5` alongside unrelated Apple anchors such as
  `com.apple/250.ApplicationFirewall`). The current-generation guard must be
  applied **after** enumeration and filtering, **before** any flush — §Q5
  already places it there; this review confirms ordering is load-bearing.
- **Exact string compare** (not a `g{N}` parse) avoids the `g1`/`g10`
  substring collision class entirely. §Q5's choice is correct; keep it.
- Sub-anchors such as `com.apple/rustynet_g10/sub` pass the prefix filter and
  would be swept. They are rustynet-created, so sweeping them is acceptable;
  note it in §Q5 so it is a decision, not an accident.
- **Naming uncertainty** (full-path vs bare child names in live output): the
  repo model pins full-path lines (`:1294-1299`), but if live pfctl emits bare
  child names, normalizing `rustynet_g*` → `com.apple/rustynet_g*` keeps the
  sweep correct. Under-sweep (missing the normalization) is fail-safe — stale
  anchors accumulate, nothing live is harmed — but the bug would be silent.
  The one-time live verification §Q5 (ii) requires stays mandatory before
  merge.

## 6. Failure modes — fail-closed posture confirmed (AMENDMENT A5)

Required posture, all consistent with existing code:

- **pf not enabled:** `list_owned_anchors` already returns `Ok(vec![])` —
  empty sweep, no error (`phase10.rs:4100-4113`); keep.
- **Top-level `-s Anchors` failure:** must keep propagating `Err`
  (`phase10.rs:4109-4112`) → the prune caller rolls back fail-closed
  (`rollback_generation_best_effort` + `force_fail_closed("owned_table_prune_failed")`,
  `phase10.rs:7209-7219`; `force_fail_closed` at `:7697`). Do not degrade
  this to best-effort.
- **Nested `-a com.apple -s Anchors` failure:** best-effort `Option`/no-op,
  mirroring `read_pf_dns_block_floor` (`macos_dns_failclosed.rs:527` and the
  fail-closed rationale at `:521-525`: a missing nested query can only limit
  which anchors are swept, never flush something live). This is the one place
  a "flush nothing on uncertainty" posture is correct *and* progress-preserving.
- **Generation-parse failure:** not reachable — the guard uses exact string
  comparison against `self.anchor_name`/`current_anchor_name()`, no parsing
  of the generation suffix (§A6). §Q5's "generation-parse failure" failure
  mode dissolves under the chosen compare form; say so.

## 7. Test sufficiency (AMENDMENTS A2, A7)

- **§Q5.6's modeled state is unreachable in production.** "live handle g2
  with `set_generation(3)`" has no production path: generation rotation
  (`:7115`/`:7121`) and the target load (`:4960-4963` at `:7149`) always leave
  `anchor_name == current_anchor_name()` at the prune. The Linux twin's test
  is likewise an artificial defensive construction (`:13939-14008`). Keep the
  artificial-state test as a defensive regression (it pins the guard against
  future edge flows), but the **primary proof** must be the
  restart-accumulation shape: fresh daemon, generation committed to 1,
  `anchor_name = Some(g1)`, owned list `[g1, g2..g5]` (stale from prior
  lifetimes plus the live g1) → flush exactly `g2..g5`, g1 untouched. This
  mirrors the focused live-lab cell §Q5 (v) already specifies (apply g1 →
  restart → apply g2 → assert g1 gone, g2 present with both DNS-block rules).
- **Existing source-pinned test survives unchanged:**
  `macos_prune_owned_tables_reestablishes_dns_floor_while_pins_live`
  (`phase10.rs:9368-9414`) pins, by source search inside the prune body, the
  `has_live_loopback_dns_pins()` probe, `apply_pf_rules(false)?` after it, and
  `Ok(())` after that. §Q5 (iv) keeps the M3 re-render
  (`phase10.rs:4839-4841`), so the pins hold; the added guard lines do not
  disturb the searched strings. §Q5 should record this — "no change needed"
  is a deliberate check, not an oversight. (Caveat: the pin requires the
  `Ok(())` to appear after the re-render; adding an early `return Ok(())`
  for an empty sweep *before* the M3 block would break the pin and the
  no-half-states ordering. Any empty-sweep fast path must come before the
  `anchor_name = None` write and still fall through to the pins-gated
  re-render, or the pin must be consciously updated.)
- **"Stale" test is actually still valid:** `owned_anchor_names_filters_only_rustynet_anchors`
  (`phase10.rs:17501-17513`) feeds top-level-style lines and asserts the
  parent `com.apple` is filtered out. `owned_anchor_names_from_output`'s
  raw-line prefix-filter contract is unchanged by the union (the union happens
  in `list_owned_anchors`), so the test needs no repair; optionally add a
  nested-dump fixture reproducing `macos_dns_failclosed.rs:1294-1299`-style
  lines. §Q5's "repair stale synthetic test" item should be dropped or
  reworded to "extend with a nested-dump fixture".
- Required test set (union of §Q5 (vi) and this review): nested-enum parse
  union; restart-accumulation prune preserve (primary); artificial
  active≠target preserve (defensive, mirroring `:13939-14008`); empty
  enumeration → zero flushes without breaking the M3 pin; sweep never
  contains `com.rustynet/blind_exit` or the bare `com.apple` parent;
  pf-not-enabled → empty, no error; allowlist accept/reject (if option 1) or
  reader-path unit tests (if option 2); nested-failure → sweep degrades to
  top-level only, prune still succeeds.

## 8. Additional confirmation: do NOT convert prune to flush-current-then-rerender

§Q5 (iv)'s refusal is correct and now has a named invariant: the existing D2
source pin (`phase10.rs:9368-9414`) encodes no-half-states ordering — the
floor re-render must gate the prune's success while pins are live. Flushing
the current anchor inside the prune would open a floor-less window even under
the M3 latch, exactly the pin-without-floor half state the D2 fix
(c4ef2583) closed. Keeping the M3 re-render as belt-and-braces
(`phase10.rs:4839-4841`) is right; the stale `:4825-4838` comment rewrite is
required and should now also drop the "previous generation" framing (§A1).

---

## Amendment summary (all docs-level changes to §Q5)

| # | Amendment |
|---|---|
| A1 | Correct `live_anchor` semantics: at the sole production prune call (`phase10.rs:7209`), `anchor_name == Some(current_anchor_name())` — the target. The "previous generation, still enforcing" comment is false; the previous anchor was rotate-flushed at `phase10.rs:4035-4039`. Keep both compares as defensive belt-and-braces, mirroring `LinuxCommandSystem::prune_owned_tables` (`phase10.rs:2897-2930`). |
| A2 | Re-scope the test plan: primary proof = restart-accumulation shape + focused live-lab cell; the §Q5.6 "live g2 with generation 3" state is unreachable in production — keep as a defensive regression labeled as artificial (mirrors `phase10.rs:13939-14008`). Record that the D2 source pin (`phase10.rs:9368-9414`) must keep passing and that any empty-sweep fast path must not break the pin's ordering. |
| A3 | The proposed allowlist arm is self-contradictory: `is_anchor_name_token("com.apple") == false` (`privileged_helper.rs:2090-2106`), so the gated variable arm never admits the nested query. Replace with either a constant-match arm `["-a","com.apple","-s","Anchors"] => Ok(())` or (preferred) reuse the direct reviewed-binary read pattern (`macos_dns_failclosed.rs:74`, `:459-468`, precedent `:526-527`). |
| A4 | State that blind_exit exclusion is structural (namespace + `com.apple`-child enumeration + `com.apple/rustynet_g` prefix filter), with `flush_anchor` (`:4115-4126`) and rotate-flush (`:4035-4039`) guards retained; keep the negative-assertion test. |
| A5 | Failure posture: nested query failure = best-effort no-op (mirror `macos_dns_failclosed.rs:527`); top-level query failure must keep propagating `Err` → `:7209-7219` rollback + `force_fail_closed`; pf-not-enabled → `Ok(vec![])`. Note the generation-parse failure mode dissolves under exact string compare. |
| A6 | Confirm guard ordering (after enumeration/filter, before flush), exact string compare (no `g{N}` parse — avoids `g1`/`g10` collisions), sub-anchor sweep acceptability (`rustynet_g10/sub` is owned), bare-child-name normalization, and mandatory one-time live verification of nested output shape before merge. |
| A7 | Drop/reword the "repair stale synthetic test" item: `owned_anchor_names_filters_only_rustynet_anchors` (`phase10.rs:17501-17513`) remains valid under the union; optionally extend with a nested-dump fixture. |

## Method note

All line citations were verified by direct reads of
`crates/rustynetd/src/phase10.rs`, `crates/rustynetd/src/privileged_helper.rs`,
`crates/rustynetd/src/macos_dns_failclosed.rs`, and
`crates/rustynetd/src/macos_exit_killswitch_precedence.rs` in this worktree,
plus grep confirmation of callers (`prune_owned_tables` production callers:
`phase10.rs:6651-6656` and `:7209` only). No code was modified, no gates run
(docs-only change), no lab touched.
