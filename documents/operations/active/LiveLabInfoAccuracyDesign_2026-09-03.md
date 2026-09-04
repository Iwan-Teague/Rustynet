# Live-Lab Information-Accuracy Design — 2026-09-03

**Status:** design proposal (docs-only; no production code changed by this document).
**Scope:** improve the *information quality* of the live-lab loop — what the orchestrator records, what the MCP servers surface, and how much of it is re-derived (wrongly) instead of reused. Every proposal is grounded in the actual code at the commit this document was written against, with `file:line` citations.
**Out of scope:** changing any security control, weakening any check, changing the run-matrix ledger schema, or shipping any lab tooling (`vm-lab` surface stays behind the default-off feature per RNQ-17).

---

## Errata + warnings applied 2026-09-04 (per adversarial review)

Per `LiveLabInfoAccuracyDesign_AdversarialReview_2026-09-04.md` (all errata re-verified by git/grep at HEAD before this edit):

1. **LANDED — Item 2 (§5.2)** landed in commit `1abc7d68`: `validator_report_ok` now returns `ValidatorVerdict { ok, reports }` (`ssh.rs:879`), and reports persist to `logs/<stage>.validator-evidence.json` (`validate_runtime.rs:255`). §5.2 marked DONE below.
2. **LANDED — Item 4 core (§5.4)** landed in commit `2c10f9d9`: `merge_rustynet_anchor_names` (`macos_dns_failclosed.rs:491`) + nested-aware `read_pf_dns_block_floor` (`:511`). §5.4 marked DONE below (the gate/tripwire part is NOT landed — see warning).
3. **PARTLY LANDED — Item 9 prune half**: `prune_owned_tables` (`phase10.rs:4847`) is generation-aware and nested-enumerating. The `orphaned_pf_anchors` drift dimension is NOT landed — Item 9 stays open for that.
4. **STAT FIX (F4)** — the QH-37 `live_two_hop_validation` figures cited in §5.8/§8 were stale. Current genuine tally from `documents/operations/live_lab_node_stage_results.csv` (stage == `live_two_hop_validation`, re-derived 2026-09-04): **134 pass / 121 fail / 559 skip** (814 rows). Do NOT use the `linux_stage_two_hop` run-matrix COLUMN — it is contaminated (AGENTS.md §12.3: traffic_test_matrix rows mislabeled as two_hop); the per-stage CSV is the evidence.
5. **SHA FIX (F5)** — §8 cited `864918d9`, which is not a valid object; the real commit is `864919d9`. Corrected below.

> **WARNING — do NOT implement §5.9's flush-current-generation post-condition or §5.4's single-filter tripwire as written.** Per adversarial review (F2/F3), these two proposals would weaken landed fail-closed controls: the landed `prune_owned_tables` preserves the current (and immediately-previous) generation *deliberately* — flushing it would strand the node in a pin-without-floor half state — and the two-filter design (broad nested-enumeration merge in `macos_dns_failclosed.rs` vs the narrow `owned_anchor_names_from_output` prefix policy in `phase10.rs:4091-4098`) is intentional; a single-filter tripwire would force unifying them and widen the generation sweep to anchors that must stay out of it. See the review, findings F2/F3. Flagged, not fixed.

---

## 1. Executive summary

A 16-tick macOS `DnsFailclosed` investigation (see §2) converged on one conclusion: **most of the wasted effort was spent reconstructing facts the system already knew but did not surface, or reconstructing them through code that disagreed with the code that rendered the verdict.**

Five concrete information failures were identified, each with a specific fix in this document:

1. **Diagnosing from post-cleanup state.** The run tears down DNS/pf configuration before anyone inspects it, so the failure scene is destroyed by the time diagnosis starts (§5.1, §5.6).
2. **Probe bugs producing false evidence.** A hand-rolled diagnostic probe double-prefixed the pf anchor path (`pfctl -a com.apple/com.apple/rustynet_gN`), found nothing, and sent the investigation down a false "floor not applied" path for multiple ticks (§5.4 makes this class structurally impossible).
3. **Terse failure strings hiding structured evidence.** The stage failure read `macos-utm-1/DnsFailclosed: validation not passed` while the daemon had already emitted a full structured drift report with `drift_reasons[]` — parsed, evaluated, and then discarded at the adapter boundary (§5.1, §5.2).
4. **Ledger columns that lie.** The run matrix's pass column has historically reported pass for stages that never passed (QH-07/QH-37); any tooling that reads the column instead of the stage's own artifact inherits the lie (§5.8).
5. **Validator and daemon observing the same control through different code that disagrees.** The daemon's `verify_live_pf_dns_floor` finds the DNS-block floor via the daemon's own anchor name (direct nested-anchor read); the `macos-dns-failclosed-check` enumerates top-level anchors via `pfctl -s Anchors`, which on macOS does not list nested anchors — so the check false-fails while the floor is present. Two observers, one control, contradictory verdicts (§5.4, §5.9).

The unifying design rule, stated once and applied nine times: **capture the evidence, not just the verdict; and every diagnostic observation must reuse the exact code path that produced the verdict.**

The top two highest-leverage items (§6): **Item 4** (shared-probe-code contract + divergence gate — permanently eliminates the false-evidence class) and **Item 2** (structured drift into the stage result — nearly free, converts every future failure from a terse string into evidence). **[2026-09-04 update: both are now LANDED — Item 2 in `1abc7d68`, Item 4's core in `2c10f9d9`; see the errata block above and §6 for the remaining ranked work.]**

---

## 2. The motivating case: tick-46 macOS `DnsFailclosed`

The observed failure: `validate_baseline_runtime` failed on `macos-utm-1` with the stage error `macos-utm-1/DnsFailclosed: validation not passed` (rendered by `orchestrator/stage/validate_runtime.rs`; at HEAD the failure strings live at `:229` — now carrying the drift reason, post-`1abc7d68` — and `:231` bare fallback).

The investigation, and where each tick's effort actually went:

- **The scene was already destroyed.** By the time the failure was diagnosed, the run's cleanup contract had torn down the pf floor and DNS pins on the guest (`orchestrator/native.rs:174` documents the "always-run cleanup contract"; `FinalCleanupStage::new` at `native.rs:846`). Guest inspection showed a plain, untouched system — indistinguishable from "never applied."
- **A hand-rolled probe lied.** A manual probe issued `pfctl -a com.apple/com.apple/rustynet_gN -s rules`, double-prefixing the anchor path (the anchor name already contains the `com.apple/` scope prefix). It returned nothing, producing several cycles of false "the floor was never applied" hypotheses.
- **Structured evidence existed and was discarded.** The daemon check (`rustynetd macos-dns-failclosed-check --no-fail-on-drift`) had emitted a full report: `overall_ok:false` plus specific `drift_reasons[]`. The orchestrator adapter (`orchestrator/adapter/ssh.rs`, `validator_report_ok`) parses that JSON, evaluates `overall_ok`, and — at this doc's base `427f3c85` — returned a **bool**, discarding the drift reasons. **[2026-09-04: no longer true — `1abc7d68` landed `ValidatorVerdict { ok, reports }` (`ssh.rs:879`, fn `:912`) and the reports now persist to `logs/<stage>.validator-evidence.json`; §5.2 is DONE.]**
- **The root cause was observer divergence, not a missing floor.** Tick 46's corrected sampler proved the floor **was present**: the daemon's own verifier (`crates/rustynetd/src/phase10.rs`, `verify_live_pf_dns_floor`, at HEAD `:4800`) reads its in-memory anchor name and issues `pfctl -a <anchor> -s rules` directly — a nested-anchor read that succeeds. The check that failed (`read_pf_dns_block_floor`, `crates/rustynetd/src/macos_dns_failclosed.rs`, at HEAD `:511`) enumerated anchors with `pfctl -s Anchors` and parsed the output with `parse_pf_anchor_names` (`macos_dns_failclosed.rs:328`); on macOS that top-level enumeration does **not** list nested anchors such as `com.apple/rustynet_g{N}`, so the check scanned zero rustynet anchors and reported the floor missing. One control, two observers, contradictory verdicts — the verdict of record came from the blind one. **[2026-09-04: the check side is fixed — `2c10f9d9` landed nested-aware enumeration via `merge_rustynet_anchor_names` (`:491`), so the check now sees nested anchors and agrees with the daemon's verifier; §5.4's core is DONE. The description above is accurate for base `427f3c85`.]**

Every item in this document is a direct answer to one of those failures, generalized so the next investigation does not repeat it.

---

## 3. Principles

**P1 — Capture the evidence, not just the verdict.** When a component evaluates a condition, the observations it evaluated (raw snapshots, parsed fields, enumerated lists) are part of the result and must survive into whatever the caller records. A bool is a verdict without provenance; it cannot be re-derived after the fact because the scene changes (P1's motivation is exactly §2: the scene *did* change — cleanup ran).

**P2 — One shared observation path.** A security-relevant control observed by two components (validator, daemon self-assert, lab probe, human diagnostic) must be observed through **one shared function**. Any second implementation is a divergence bug waiting to fire — the two implementations *will* disagree eventually (§2 item 5 is the proof), and the disagreement will be misread as a product failure.

**P3 — The stage's own artifact is the only source of truth.** Run-matrix CSV columns are projections, and projections have lied before (QH-07/QH-37). Tooling reads stage status from the stage's own report artifact; columns are for humans scrolling history, never for programs.

**P4 — Fail closed, observe read-only.** Evidence capture never mutates guest state (except where explicitly specified, e.g. §5.6's cleanup-hold, which is default-off). New observation paths reuse the existing privileged-exec hardening: argv-only, validated tokens, fixed program paths (`REVIEWED_PFCTL_PATH`, `macos_dns_failclosed.rs:74`).

**P5 — Design for the second investigation.** Every artifact added here is shaped so the *next* failure can be diagnosed from the recorded evidence alone — without re-running the lab, without SSHing into a torn-down guest, without re-deriving a probe by hand.

---

## 4. Grounding map

Key symbols referenced throughout (all paths repo-relative; commit `427f3c85`):

| Symbol | Location | Role |
| --- | --- | --- |
| `DaemonProbeOp` | `crates/rustynet-cli/src/vm_lab/mod.rs:10139` | Enum of the six validator probes (`RuntimeAcls`, `ServiceHardening`, `KeyCustody`, `Authenticode`, `MeshStatus`, `DnsFailclosed`), `as_str()` at :10156. |
| `DaemonProbe` trait | `vm_lab/mod.rs:10173` | `build_argv` / `build_argv_with_extra_args` (:10191, validates each extra arg as a single shell-safe token `[alnum -_.:/]`); per-platform impls `LinuxDaemonProbe` :10221, `WindowsDaemonProbe` :10257, `MacosDaemonProbe` :10284; `daemon_probe_for()` dispatch :10350. |
| `remote_exec_for()` | `vm_lab/mod.rs:10115` | Platform SSH adapter dispatch (`PosixRemoteExec`/`WindowsRemoteExec`/`UnsupportedRemoteExec`). |
| `validator_report_ok` | `orchestrator/adapter/ssh.rs:884-927` | Parses daemon check JSON typed and fail-closed; returns **bool only**; `json_object_candidates` scanner at :930-975. The evidence-discard point. **[2026-09-04: LANDED — returns `ValidatorVerdict { ok, reports }` (`ssh.rs:879`, fn `:912`); line numbers stale at HEAD.]** |
| `validate_runtime` stage | `orchestrator/stage/validate_runtime.rs` | OPS list :93-98; `ValidatorResult{op, passed, summary}` :139-155; terse failure strings :158-159; best-effort `validator_results.json` (bools+summaries only) :163-168; `probe_expectations` :60-67 (only MeshStatus gets extra args). |
| `verify_live_pf_dns_floor` | `crates/rustynetd/src/phase10.rs:4770-4792` (HEAD `:4800`) | Daemon's floor verifier: direct nested-anchor read via its own in-memory anchor name; fails with `DnsApplyFailed` if UDP or TCP/53 block rule missing. |
| `list_owned_anchors` / `owned_anchor_names_from_output` | `phase10.rs:4100` / `:4091-4098` | Top-level `pfctl -s Anchors` enumeration, filtered to the `com.apple/rustynet_g` prefix. |
| `read_pf_dns_block_floor` / `parse_pf_anchor_names` | `macos_dns_failclosed.rs:492-507` (HEAD `:511`) / `:328` | Check-side floor read: blind top-level enumeration (root cause A). **[2026-09-04: LANDED as nested-aware — `2c10f9d9` added `merge_rustynet_anchor_names` (HEAD `:491`).]** |
| `prune_owned_tables` | `phase10.rs:4817-4843` (HEAD `:4847`) | Flushes every `list_owned_anchors()` result — same blind enumeration (§5.9). **[2026-09-04: LANDED as generation-aware + nested-enumerating; preserves the current/previous generation deliberately.]** |
| `collect_macos_dns_failclosed_snapshot` | `macos_dns_failclosed.rs:540-554` | Snapshot builder: resolv.conf, scutil, pf, networksetup, scoped-resolver presence. |
| `build_macos_dns_failclosed_report_for_posture` | `macos_dns_failclosed.rs:570-583` | `MacosDnsFailclosedReport { schema_version: 2, posture, overall_ok, snapshot, drift_reasons }`; posture threaded by caller, never inferred (tautology note :565-569). |
| `macos_dns_posture` | `phase10.rs:801` | Derivation: `FullTunnel` → `FullyProtected`; `Off` + `serve_exit_node` → `FullyProtected`; else `ScopedResolverOnly`. Threaded at `daemon.rs:8895` and `daemon.rs:10635`. |
| `collect_failure_diagnostics` | `orchestrator/diagnostics.rs:19` | Pre-cleanup failure diagnostics → `diagnostics/rust-native-failure/` (dir :27, artifacts :40, `summary.json` :125); `TimeoutAwareStageRecorder` :642+ writes `logs/` :674; timeout taxonomy :817-840. |
| Pre-cleanup hook wiring | `orchestrator/native.rs:791-805, 815-818` | Closure runs `collect_failure_diagnostics` when any stage failed, **before** the always-run cleanup (:174; `FinalCleanupStage::new` :846). |
| `stub_id` / `enforce_launch_gate` / `RecordStagePatchConfig` | `crates/rustynet-cli/src/live_lab_stage_triage.rs:112` / `:464-505` / `:143` | Launch gate + `ops live-lab-record-stage-patch`; stub id = `{run_id}::{stage}`; gate prints fill-command template with a **literal** `<stub_id>` placeholder. |
| MCP lab-state tool surface | `crates/rustynet-mcp/src/bin/lab_state.rs` | Existing registrations: `get_vm_diagnostics` :4813, `diagnose_live_lab_failure` :4833, `get_run_result` :4951, `read_report_artifact` :4981, `grep_report` :4993, `get_stage_log` :5006, `stage_triage_history` :5100; dispatch match :6053-6187. No `get_stage_result` / `lab_probe_node` / `lab_node_intent` exists today. |
| Artifact-writer companions | `crates/rustynetd/src/macos_exit_dns_failclosed.rs:104` (writes `macos_dns_failclosed_check.json` :121-123), `crates/rustynetd/src/linux_exit_dns_failclosed.rs:112` (writes `linux_dns_failclosed_check.json` :124-126) | Existing partial coverage for evidence persistence on the exit-node path — the baseline-runtime path lacks the equivalent. |
| Per-OS check siblings | `crates/rustynetd/src/linux_dns_failclosed.rs` (evaluate :85, build_report :191, collect :245-282), `crates/rustynetd/src/windows_dns_failclosed.rs` (lib.rs :89), `macos_dns_sc_protect.rs` | Same report shape per OS; designs here apply uniformly. |

---

## 5. Per-item specifications

### 5.1 Item 1 — Failure-time evidence bundle

**Problem.** On stage failure the only on-guest evidence captured is the generic `collect_failure_diagnostics` harvest; the *specific* state the failing validator judged (pf rulesets, DNS resolver configuration, service pins) is torn down by cleanup immediately after, so the failure scene is unrecoverable.

**Interface — orchestrator hook point.** Extend the existing pre-cleanup hook rather than inventing a new one:

- Add an `evidence_bundle()` step to the validator flow: extend the `DaemonProbe` trait (`vm_lab/mod.rs:10173`) with one method:
  `fn evidence_bundle_ops(&self, op: DaemonProbeOp) -> Vec<EvidenceCommand>` where `EvidenceCommand { label: String, argv: Vec<String> }` — a fixed, per-`op`, per-platform list of read-only observation commands.
- Wire the execution into `collect_failure_diagnostics` (`orchestrator/diagnostics.rs:19`): after the existing generic harvest, for each failed `ValidatorResult` on each node, execute the corresponding evidence commands through the platform's `remote_exec_for()` adapter (`vm_lab/mod.rs:10115`) and write each output to:
  `diagnostics/rust-native-failure/evidence/<alias>/<op>/<label>.txt`
- Because the hook already runs before cleanup (`native.rs:791-805` passes `pre_cleanup_diagnostics` into `run_with_observer_and_pre_cleanup_hook` at `:815-818`), the bundle captures the live failure scene with **no change to the cleanup contract**.

**Data shape.** `diagnostics/rust-native-failure/evidence/index.json`:
```json
{ "schema_version": 1, "run_id": "livelab-…", "stage": "validate_baseline_runtime",
  "bundles": [ { "alias": "macos-utm-1", "op": "DnsFailclosed",
                 "files": ["pfctl-s-Anchors.txt", "pfctl-a-com-apple-s-Anchors.txt",
                            "scutil-dns.txt", "networksetup-dnsservers.txt",
                            "resolver-dir-listing.txt", "daemon-log-tail.txt"],
                 "captured_at_utc": "2026-09-03T12:00:00Z" } ] }
```

**Grounding / reuse.** The per-platform probe argv machinery (`build_argv` at `vm_lab/mod.rs:10173+`, platform impls :10221/:10257/:10284) already solves "run a daemon-side check over SSH with argv-only hardening"; evidence commands reuse it. The exit-node path already proves the value of persisted check artifacts: `write_macos_exit_dns_failclosed_artifacts` (`macos_exit_dns_failclosed.rs:104`, writes `macos_dns_failclosed_check.json` :121-123) and its Linux twin (`linux_exit_dns_failclosed.rs:112`). This item gives the baseline-runtime path the same persistence, broadened to all six probes.

**Existing partial coverage.** `collect_failure_diagnostics` (`diagnostics.rs:19-125`) captures daemon status/journal tails generically; item 1 adds the *validator-scoped* observations. Do not duplicate the generic harvest — extend it.

**Effort / risk / security / deps.** Effort **M**. Risk: low (observe-only; fixed command lists, no user-supplied argv — the `build_argv_with_extra_args` token-validation rule at `vm_lab/mod.rs:10191` is inherited but evidence commands take no extras). Security: all commands read-only (`pfctl -s …`, `scutil --dns`, `networksetup -getdnsservers`, directory listings, log tails); fixed program paths (`REVIEWED_PFCTL_PATH`, `macos_dns_failclosed.rs:74`); outputs contain no key material by construction (pf rulesets, resolver config, service state). Deps: item 4 (the evidence commands must share the fixed observation code so they cannot lie like the hand-rolled probe did — P2).

**Example — the `DnsFailclosed` bundle.** With this in place, tick 46's diagnosis is: open `evidence/macos-utm-1/DnsFailclosed/pfctl-a-com-apple-s-Anchors.txt`, see `rustynet_g3` listed under `com.apple`, open `pfctl-a-com-apple-rustynet_g3-s-rules.txt`, see the two `block drop` rules for udp/53 and tcp/53 — floor present, check blind. Three file reads replace ~10 investigation ticks.

**Concrete `DnsFailclosed` command set (macOS):**
1. `pfctl -s Anchors` (top level)
2. `pfctl -a com.apple -s Anchors` (nested — the level the check misses)
3. For each anchor matching `com.apple/rustynet_g*` found in (1)+(2): `pfctl -a <anchor> -s rules`
4. `scutil --dns`
5. `networksetup -listallnetworkservices` + `-getdnsservers` per service
6. Listing of `/etc/resolver/` (the `MACOS_SCOPED_RESOLVER_PATH` surface consumed at `macos_dns_failclosed.rs:551-552`) + contents
7. `/etc/resolv.conf`
8. Daemon status/posture + journal tail (already in the generic harvest; referenced by path, not duplicated)

Linux/Windows equivalents mirror the per-OS collect functions (`linux_dns_failclosed.rs:245-282`, `windows_dns_failclosed.rs`), so the bundle set is defined once per op per platform in the probe impl.

---

### 5.2 Item 2 — Structured drift in the stage result

> **[2026-09-04: DONE — landed in commit `1abc7d68`.** `validator_report_ok` returns `ValidatorVerdict { ok: bool, reports: Vec<serde_json::Value> }` (`ssh.rs:879`, fn `:912`), reports thread into validator results and persist to `logs/validate_baseline_runtime.validator-evidence.json` (`validate_runtime.rs:255`, schema comment `:89`), and the failure string carries the drift reason (`validate_runtime.rs:229`). Verdict rules unchanged. Text below retained as the original design rationale.**]**

**Problem.** `validator_report_ok` (`orchestrator/adapter/ssh.rs:884-927`) parses the daemon's typed check JSON — including `drift_reasons` — and returns only a bool (`validate_runtime.rs:158` then renders `"{alias}/{op:?}: validation not passed"`). The evidence the daemon already produced is discarded at the one place the orchestrator holds it.

**Interface — code change + artifact.**

- Change `validator_report_ok` to return `ValidatorReport { ok: bool, reports: Vec<serde_json::Value> }` — the parsed reports verbatim, one per JSON object found by the existing `json_object_candidates` scanner (`ssh.rs:930-975`). The fail-closed evaluation rules (:884-927: empty/truncated/non-JSON/field-missing → `ok:false`; `overall_ok:false` anywhere → false; inconsistent `overall_ok:true` + non-empty `drift_reasons` → false) are unchanged — this item changes what is *kept*, not what is *judged*.
- Thread `reports` into `ValidatorResult` (`validate_runtime.rs:139-155`) as `report: Option<serde_json::Value>` (last/merged report per node+op).
- Extend the best-effort per-stage artifact `validator_results.json` (:163-168) with the reports, **and** write a per-stage evidence artifact `logs/validate_baseline_runtime.validator-evidence.json` (name pattern: `logs/<stage>.validator-evidence.json`) with schema:
```json
{ "schema_version": 1, "stage": "validate_baseline_runtime",
  "results": [ { "alias": "macos-utm-1", "op": "DnsFailclosed", "passed": false,
    "report": { "schema_version": 2, "posture": "fully_protected",
      "overall_ok": false,
      "drift_reasons": ["pf DNS-block floor not observed in any scanned anchor (anchors_scanned=0)"],
      "snapshot": { "pf": { "anchors_scanned": 0, "block_rules_present": false },
                     "networksetup_readable": true, "scoped_resolver_present": false } } } ] }
```
- The daemon's report shape (`MacosDnsFailclosedReport`, `macos_dns_failclosed.rs:570-583`, `schema_version: 2`) is embedded **verbatim** under `report` — the orchestrator must not re-shape or summarize daemon evidence (P1; re-shaping is how evidence gets lost a second time).

**Grounding / reuse.** Everything needed already exists: the typed parse (:884-927), the scanner (:930-975), the artifact-writing precedent (`validator_results.json` :163-168, exit-node check JSON writers cited in §4). This is a *plumbing* item.

**Existing partial coverage.** `diagnose_live_lab_failure` (MCP, `lab_state.rs:4833`) reads `failure_digest.json` — which today inherits the terse strings. With item 2 landed, the digest can quote the first drift reason instead.

**Effort / risk / security / deps.** Effort **S**. Risk: low. Security: none weakened — the verdict logic is untouched; `drift_reasons` are diagnostic text produced by the daemon (already validated today, just dropped); no secrets in reports by construction. Deps: none (independent of item 4, though item 4 fixes the *content* accuracy of these reports for the pf case).

**Example impact.** Stage failure becomes: `macos-utm-1/DnsFailclosed: validation not passed — drift: pf DNS-block floor not observed in any scanned anchor (anchors_scanned=0)`. The `anchors_scanned=0` alone points straight at the enumeration blind spot.

---

### 5.3 Item 3 — `lab_probe_node` MCP tool

**Problem.** Diagnosing a node requires either a full lab run or hand-rolled SSH probes (the double-prefix bug came from exactly this hand-rolling). The validator's checks are one `rustynetd <plat>-<op>-check` invocation away, but no tool exposes that on demand with structured output.

**Interface — new MCP tool in `rustynet-mcp-lab-state`** (following the existing name→handler registration pattern at `lab_state.rs:4813-5100` and dispatch at `:6053-6187`):

```
tool:    lab_probe_node
args:    { "alias": "macos-utm-1",
           "probe": "dns-failclosed",            // one of DaemonProbeOp::as_str() values
           "extra_args": ["--json"] }            // optional; each token validated
returns: { "alias": "macos-utm-1", "probe": "dns-failclosed",
           "exit_code": 0,
           "parsed_ok": true,
           "report": { … daemon check JSON, verbatim … },
           "argv_used": ["/opt/rustynet/bin/rustynetd",
                          "macos-dns-failclosed-check", "--no-fail-on-drift", "--json"] }
```

Valid `probe` values (from `DaemonProbeOp::as_str()`, `vm_lab/mod.rs:10156`): `runtime-acls`, `service-hardening`, `key-custody`, `authenticode`, `mesh-status`, `dns-failclosed`.

**Grounding / reuse.** The argv construction **must** call `daemon_probe_for(alias_platform)` (`vm_lab/mod.rs:10350`) and `build_argv` — not re-derive the daemon check subcommand name. This is the P2 rule applied to tooling: the MCP probe and the orchestrator validator literally share `LinuxDaemonProbe:10221` / `WindowsDaemonProbe:10257` / `MacosDaemonProbe:10284`, so a subcommand rename updates both. `--no-fail-on-drift` is appended as the validators do, so exit code is always 0 and the verdict comes from the report body (existing convention, `ssh.rs:868-875` comment). The response is parsed with the same typed, fail-closed rules as `validator_report_ok` (`ssh.rs:884-927`) — ideally by calling the same function extracted into a shared location.

**Existing partial coverage.** `get_vm_diagnostics` (`lab_state.rs:4813`) collects daemon status/journal — a different, coarser surface (no per-probe check, no structured drift). The ai-agent server's `lab_guest_exec` runs arbitrary read-only guest commands but returns raw text, not typed check reports. `lab_probe_node` is the structured, argv-hardened middle ground; it does not replace either.

**Effort / risk / security / deps.** Effort **M** (MCP plumbing + shared-code extraction). Risk: low. Security: argv-only exec on the guest; `extra_args` pass through `build_argv_with_extra_args`' single-shell-safe-token validation (`vm_lab/mod.rs:10191`); probes are observe-only; the tool targets lab inventory nodes only (same authorization model as the other lab-state tools). Deps: benefits from item 4 (probe correctness), but ships independently.

**Example — the `DnsFailclosed` case.** `lab_probe_node(macos-utm-1, dns-failclosed)` against a live guest returns the report with `drift_reasons: ["pf DNS-block floor not observed in any scanned anchor (anchors_scanned=0)"]` and `snapshot.pf.anchors_scanned: 0` — a one-call reproduction of the false failure, impossible to mis-type because no human constructs the argv.

---

### 5.4 Item 4 — Shared-probe-code contract + divergence gate

> **[2026-09-04: core DONE — landed in commit `2c10f9d9`.** `merge_rustynet_anchor_names(top_output, nested_output)` (`macos_dns_failclosed.rs:491`) unions `pfctl -s Anchors` with `pfctl -a com.apple -s Anchors` and `read_pf_dns_block_floor` (`:511`) scans each anchor's rules, still fail-closed. The check now sees nested anchors — §5.4's worked example is shipped behavior, not a proposal. **NOT landed:** the §5.4.2 divergence gate/tripwire — see the warning below; do NOT implement it as written.**]**

**Problem.** The controlling defect of §2: `verify_live_pf_dns_floor` (`phase10.rs:4770-4792`) observes the floor via the daemon's own anchor name (nested read, correct); `read_pf_dns_block_floor` (`macos_dns_failclosed.rs:492-507`) observes it by enumerating top-level anchors via `parse_pf_anchor_names` (`:328`) — blind to nested anchors on macOS. The check false-fails while the floor is live. `prune_owned_tables` (`phase10.rs:4817-4843`) shares the same blind enumeration (see §5.9).

**Interface — refactor + gate.**

1. **Extract one enumeration function** in `rustynetd`: `enumerate_owned_pf_anchor_names(output_top: &str, output_nested: &str) -> Vec<String>` — the shared, prefix-filtered (`com.apple/rustynet_g*`, reusing `owned_anchor_names_from_output` logic at `phase10.rs:4091-4098`) anchor-set derivation that takes the outputs of both enumeration levels (`pfctl -s Anchors` and `pfctl -a com.apple -s Anchors`). All three consumers call it:
   - `read_pf_dns_block_floor` (`macos_dns_failclosed.rs:492-507`) — the check now scans nested anchors, so it sees what the daemon's verifier sees;
   - `prune_owned_tables` (`phase10.rs:4817-4843`) — flush actually reaches everything the check can see;
   - `list_owned_anchors` (`phase10.rs:4100`) — becomes the fetch-and-parse wrapper around the shared parser.
   Note `verify_live_pf_dns_floor` (:4770-4792) intentionally does *not* enumerate — it reads the daemon's own anchor by name, which is strictly more precise; the shared function's contract is "what an outside observer can see," and the divergence gate below keeps the two honest against each other.
2. **Divergence gate.** A `rustynetd` unit test + a `scripts/ci/` gate check asserting: for a fixture `pfctl -s Anchors` + `pfctl -a com.apple -s Anchors` output pair, (a) the shared enumeration returns the nested rustynet anchors, (b) `read_pf_dns_block_floor`'s anchor set == the shared enumeration's, and (c) a fixture where the floor exists in a nested anchor evaluates `overall_ok: true`. The gate fails if any consumer re-implements anchor parsing (a grep tripwire over `rustynetd` sources for a second `starts_with("com.apple/rustynet_g")`-style filter outside the shared module — same tripwire pattern as the existing boundary-leakage gates).
3. **Contract statement** (for the docs this design feeds): *a validator OS-observation and the daemon's self-observation of the same control must both route through one shared function; a new check that re-implements an existing observation fails the gate* (P2, mechanized).

> **WARNING (2026-09-04, per adversarial review F3): the §5.4.2 single-filter grep tripwire must NOT be implemented as written.** The landed tree intentionally has **two** filters: the check uses the broader `parse_pf_anchor_names` filter via `merge_rustynet_anchor_names` (`macos_dns_failclosed.rs:491`), while `phase10.rs:4091-4098` keeps the narrower `owned_anchor_names_from_output` **by design** (its comment at `:4112-4126`: the narrow filter keeps the fixed-name `com.rustynet/nat` exit-NAT anchor and `com.rustynet/blind_exit` out of the generation sweep). Unifying the filters to satisfy a single-filter tripwire would widen the flush/generation sweep to anchors that must stay out of it. Any gate must encode the two-filter contract (one shared *nested-enumeration merge* per consumer family, distinct prefix policies), not a single-filter tripwire.

**Grounding / reuse.** All cited above; no new privileged commands — the nested enumeration level is one additional existing `pfctl` invocation (`pfctl -a com.apple -s Anchors`) using the same fixed-path `run_capture(PrivilegedCommandProgram::Pfctl)` path as `list_owned_anchors` (`phase10.rs:4101`).

**Existing partial coverage.** `owned_anchor_names_from_output` (`:4091-4098`) already centralizes the *filter*; item 4 centralizes the *enumeration levels* too.

**Effort / risk / security / deps.** Effort **M**. Risk: medium — this touches live pf handling in `phase10.rs`; mitigation: the flush path (`prune_owned_tables`) only ever gains visibility (anchors it previously could not see are precisely the stale-generation residue §5.9 targets), and `flush_anchor`'s blind-exit skip (`:4115-4126`) is preserved untouched. Security: **strengthens** — a check that currently false-fails starts passing only when the floor is genuinely observable through the same path the daemon itself uses; no check is weakened, no allow-path added. Deps: prerequisite for item 1's evidence command correctness and item 9.

**Example — `DnsFailclosed`.** After the refactor, `read_pf_dns_block_floor` scans `rustynet_g3` under `com.apple`, finds both DNS block labels (`anchor_rules_contain_both_dns_block_labels`, `macos_dns_failclosed.rs:347`), and returns a present floor; the check agrees with `verify_live_pf_dns_floor`; the false failure class is gone at the source rather than explained away in a tick log.

---

### 5.5 Item 5 — `lab_node_intent` MCP tool

**Problem.** In the motivating investigation, a plain-client node (expected posture `ScopedResolverOnly`) was momentarily confused with a full-tunnel exit (expected `FullyProtected`), costing diagnosis time. The node's *assigned intent* exists in the distributed assignment bundle but is not queryable; the only way to learn "what was this node supposed to be?" is to re-read orchestrator internals by hand.

**Interface — new MCP tool in `rustynet-mcp-lab-state`:**

```
tool:    lab_node_intent
args:    { "alias": "macos-utm-1", "run_id": "livelab-1788325534-2e7bdaf7bf57" }   // run_id optional: default latest run whose report dir records the node
returns: { "alias": "macos-utm-1", "run_id": "livelab-…",
           "assigned_role": "client",
           "exit_mode": "off",
           "serve_exit_node": false,
           "expected_dns_posture": "scoped_resolver_only",
           "expected_dimensions": { "pf_dns_floor": false, "scoped_resolver": true,
                                     "networksetup_pin_free": true },
           "derivation": "macos_dns_posture(exit_mode=off, serve_exit_node=false) -> ScopedResolverOnly (phase10.rs:801)" }
```

**Grounding / reuse.** The derivation is not new logic — it **calls the same function the daemon calls**: `macos_dns_posture(exit_mode, serve_exit_node)` (`phase10.rs:801`, threaded into the daemon at `daemon.rs:8895` and `daemon.rs:10635`). The assignment data lives in the bundles built by the setup stage's assignment distribution (`build_bundle_env`); the orchestrator already persists per-node role/assignment in the report dir (resolved plan / role assignment artifacts under `orchestrator/role_assignment.rs` / `resolved_plan.rs`). The tool joins those persisted artifacts with the posture derivation. Platform gate: for non-macOS nodes, return the Linux/Windows posture expectation from the equivalent per-OS check modules (`linux_dns_failclosed.rs`, `windows_dns_failclosed.rs`).

**Existing partial coverage.** `get_lab_topology` exposes role/mesh-ip digests but not the derived expected posture; `get_run_result` exposes stage outcomes, not per-node intent. No duplication — this is a join + derivation surface.

**Effort / risk / security / deps.** Effort **M**. Risk: low. Security: read-only; intent is not trust state — the tool reports what was assigned, it does not authenticate it (the signed-bundle path already does that; this tool must document that distinction to prevent anyone treating its output as verification). Deps: none.

**Example — the `DnsFailclosed` case.** `lab_node_intent(macos-utm-1)` returning `expected_dns_posture: scoped_resolver_only, expected_dimensions.pf_dns_floor: false` would have killed the "floor should be present" hypothesis in one call — and, post-item-4, the *check itself* would evaluate against the threaded posture exactly as the daemon does (`build_macos_dns_failclosed_report_for_posture`, `macos_dns_failclosed.rs:570-583`, posture threaded by caller :565-569 note).

---

### 5.6 Item 6 — Hold-on-failure mode

**Problem.** The always-run cleanup contract (`native.rs:174`; `FinalCleanupStage::new` :846) destroys the failure scene (§2 item 1). Item 1 captures a bundle, but some diagnoses need the live scene (reproduce a probe, inspect with different eyes).

**Interface — orchestrator flag + TTL safety net.**

- Add `--hold-on-failure` (default **off**) to the orchestrate entry point. When the run finishes `failed` **and** the flag is set: skip the final cleanup stage, and write `cleanup_pending.json` (timestamp, run_id, aliases skipped, reason) into the report dir + a marker in the run summary.
- TTL fallback: the *next* orchestrate launch (and a new `ops vm-lab-hold-release --all`) scans for `cleanup_pending.json` older than a per-run TTL (default 6h) and executes the deferred cleanup before proceeding. This bounds how long guest state can stay mutated without an explicit operator action, so an interrupted session cannot leave pf/DNS mutations live indefinitely.
- Scope restriction: hold-on-failure may not skip cleanup on a guest holding the `blind_exit` role — blind-exit state is irreversible by design (§10.7 of AGENTS.md) and its cleanup path is part of the control; the flag is rejected (fail closed) if the failed topology includes a blind-exit node. Same posture for exit-NAT residue: the reconcile path (`reconcile_exit_nat_residue`, `phase10.rs:4845-4898`) must still run on hold — only the *posture* teardown (DNS floor, pins) is deferred. Concretely: hold defers only `FinalCleanupStage`'s DNS/pf posture teardown, never the NAT-residue reconciliation, never the membership revocation bookkeeping.

**Grounding / reuse.** The hook ordering already exists (pre-cleanup diagnostics at `native.rs:791-805` run before `run_with_observer_and_pre_cleanup_hook` at `:815-818`); item 6 makes the *subsequent* cleanup stage conditionally skippable — a flag threaded into the runner's final stage decision, plus the marker + TTL sweep. `run_history.rs` already tracks run records for the TTL scanner to consult.

**Existing partial coverage.** Item 1 (evidence bundle) covers most diagnostic needs without holding; item 6 is for the residual cases that need the live scene. Partial in-run coverage: stage-level `rerun_stage`/`resume_from` can re-enter setup without a full cleanup, but do not preserve a *failed* scene either.

**Effort / risk / security / deps.** Effort **M**. Risk: medium — deferred cleanup is a mutation-lifetime extension on lab guests. Mitigations: default off; TTL sweep; blind-exit and NAT-residue exclusions (fail-closed rejection); hold state is recorded in the report dir so any subsequent run sees it. Security: the flag never weakens a shipped-path control (this is lab-only surface behind the `vm-lab` feature, RNQ-17); guests are lab-only; the strictest-secure-default rule is honored by the default and the TTL. Deps: independent; composes with items 1/3.

**Example — the `DnsFailclosed` case.** With hold-on-failure, the guest keeps the applied floor and pins; `lab_probe_node(macos-utm-1, dns-failclosed)` (item 3) reproduces the check against the *live* scene, and a manual `pfctl -a com.apple/rustynet_g3 -s rules` (correctly typed this time — the argv comes from the item-1 evidence command list) confirms the floor directly.

---

### 5.7 Item 7 — Launch-gate ergonomics

**Problem.** `enforce_launch_gate` (`live_lab_stage_triage.rs:464-505`) refuses launch while a planned stage has an unfilled triage stub (correct, no-bypass-by-design), but its remedy line prints the fill command with a **literal `<stub_id>` placeholder** — the operator must manually resolve `livelab-<epoch>-<commit8>::<stage>` and risk a typo that sends the patch to the wrong stub (the ledger refuses overwrites, so a typo'd successful fill pollutes the wrong record).

**Interface — two changes, both in `live_lab_stage_triage.rs`.**

1. **Substitute the resolved stub id.** The gate already has the run-id prefix and the failing stage per record; instead of the template, print the fully-formed command per record:
   ```
   ops live-lab-record-stage-patch --stub-id livelab-1788325534-2e7bdaf7bf57::validate_baseline_runtime --patch "<one-line fix summary; 'none: <reason>' if no patch>"
   ```
   The stub id is exactly `stub_id(run_id, stage)` (`:112` — `format!("{run_id}::{stage}")`), and the gate's failure message already enumerates records with their `stub_id` values, so this is pure string plumbing in the existing message builder.
2. **Accept a run/job reference.** Extend `RecordStagePatchConfig` (`:143`) with `--from-run <run_id>` (and accept a job id, resolving to the run's report dir → recorded run id): when given, the executor enumerates the ledger's unfilled stubs whose id starts with `<run_id>::`, requires exactly one per `--stage` (ambiguity → explicit error listing the candidates; **never** silently pick), and fills it. This reuses the existing XOR addressing rules in `execute_ops_record_stage_patch` (`:154`) — `--from-run` is a *resolver* for `stub_id`, not a third addressing mode (it errors exactly like the existing mutual-exclusion errors: "pass either --stub-id or --run-id with --stage").

**Grounding / reuse.** Everything cited above is in the one file; the ledger's overwrite-refusal (`fill_patch` refuses a filled stub) stays as the backstop if a stale reference resolves wrong.

**Existing partial coverage.** `stage_triage_history` (MCP, `lab_state.rs:5100`) lists past attempts per stage; it does not resolve stub ids for filling. The gate itself is the enforcement; this item only fixes its remedy ergonomics.

**Effort / risk / security / deps.** Effort **S**. Risk: low. Security: none — the gate's no-bypass property is untouched; the resolver refuses ambiguity fail-closed; no new write paths (fills go through the existing executor with its overwrite protection). Deps: none.

**Example.** Tick-46-adjacent flow: gate refuses launch → operator pastes the printed, fully-resolved command → done in one step instead of (list stubs, guess the epoch, re-run, discover typo, hand-repair).

---

### 5.8 Item 8 — `get_stage_result` MCP tool (artifact-first, never the CSV column)

**Problem.** The run-matrix CSV pass column has lied before (QH-07: comma-naive parsing produced confidently wrong conclusions; QH-37 family: a column reporting pass for a stage whose lifetime record contains zero passes — `live_two_hop_validation`, whose genuine per-stage tally is **134 pass / 121 fail / 559 skip** in `documents/operations/live_lab_node_stage_results.csv` as of 2026-09-04). Programmatic consumers need a tool that structurally cannot inherit a column lie.

**Interface — new MCP tool in `rustynet-mcp-lab-state`:**

```
tool:    get_stage_result
args:    { "run_id": "livelab-1788325534-2e7bdaf7bf57",       // or report_dir
           "stage": "validate_baseline_runtime" }
returns: { "run_id": "…", "stage": "…",
           "status": "failed",                     // from the stage's OWN artifact row in state/stages.tsv
           "rc": 1,
           "duration_secs": 412.7,
           "data": { …the stage's structured artifact, verbatim, if present… },
           "artifact_paths": ["state/stages.tsv", "logs/validate_baseline_runtime.log",
                               "logs/validate_baseline_runtime.validator-evidence.json",
                               "diagnostics/rust-native-failure/summary.json"],
           "ledger_column": { "value": "fail", "matches_artifact": true } }
```

**Grounding / reuse.** `get_stage_log` (`lab_state.rs:5006`) already locates the stage row in `state/stages.tsv` and tails the log; `get_run_result` (`:4951`) resolves run → report dir; `read_report_artifact` (`:4981`) fetches raw files. The new tool composes those internals and adds: (a) the stage's structured `data` artifact when one exists (item 2's `validator-evidence.json`, or the stage registry's own result blob), (b) the explicit `ledger_column` cross-check so a mismatch is *surfaced* rather than silent (P3 mechanized: the artifact is authoritative, the column is reported for contrast).

**Existing partial coverage.** Deliberately no duplicate of `read_report_artifact` (raw file) or `grep_report` (search) — this tool answers "what did stage X conclude" in one call, from the artifact, with the column-hygiene check attached.

**Effort / risk / security / deps.** Effort **M**. Risk: low. Security: read-only; report-dir path confinement inherited from the existing tools. Deps: richer `data` with item 2; standalone otherwise.

**Example — the `DnsFailclosed` case.** `get_stage_result(run, "validate_baseline_runtime")` returns `status: "failed"` with `data.results[].report.drift_reasons` inline — the one call a reviewer (or the second-reviewer agent) needs, with no opportunity to read a lying column.

---

### 5.9 Item 9 — Anchor/generation hygiene (orphaned-anchor drift)

> **[2026-09-04: PARTLY LANDED.** The prune half is done: `prune_owned_tables` (`phase10.rs:4847`) is generation-aware (preserves the current + immediately-previous generation, skips the blind-exit anchor; per `MacosPruneNestedAnchorHygieneReview_2026-09-03`) and `list_owned_anchors` (`:4100`) unions the nested `com.apple` sub-anchor set. The `orphaned_pf_anchors` drift dimension is NOT landed — Item 9 remains open for it. **WARNING: §5.9.3's flush-current-generation post-condition must NOT be implemented as written — see below.****]**

**Problem.** macOS pf anchors are per-generation (`com.apple/rustynet_g{N}`), and generation churn (re-apply loops, daemon restarts, cleanup/re-apply cycles — exactly what an investigation *causes*) can strand old generations. `prune_owned_tables` (`phase10.rs:4817-4843`) flushes every `list_owned_anchors()` result, but that enumeration is top-level-blind (§5.4) — so the anchors the enumeration cannot see are precisely the ones that accumulate. Nothing currently reports "you own pf anchors your enumeration cannot see."

**Interface — drift dimension + shared enumeration.**

1. Prerequisite: item 4's shared nested-aware enumeration — prune's blind spot and the check's blind spot are the same bug; fix once.
2. Add an `orphaned_pf_anchors` drift dimension to the macOS failclosed check (`evaluate_macos_dns_failclosed_snapshot_for_posture`, `macos_dns_failclosed.rs:611-651`): the snapshot's pf section gains `owned_anchor_names: Vec<String>` (from the shared enumeration) and `current_anchor_name: Option<String>` (the daemon's own in-memory anchor, same source `verify_live_pf_dns_floor` reads at `phase10.rs:4771-4773`); any owned anchor ≠ current is a drift reason `orphaned_pf_anchors: ["com.apple/rustynet_g1", …]` (warning-grade for the floor-bearing generation, error-grade if a *stale* anchor still carries DNS block rules — a stranded floor is a live default-deny mutation on a non-exit path).
3. Prune verification: `prune_owned_tables`' post-condition test — after flush, the shared enumeration returns zero `com.apple/rustynet_g*` anchors (except the protected blind-exit anchor, `flush_anchor` skip at `:4115-4126`, which stays out of both enumeration-driven flush and drift).

> **WARNING (2026-09-04, per adversarial review F2): the §5.9.3 post-condition must NOT be implemented as written.** The landed `prune_owned_tables` (`phase10.rs:4847`) deliberately **preserves the current generation** (and the immediately-previous one) — flushing it would strand the node in a pin-without-floor half state. The post-condition as written ("zero `com.apple/rustynet_g*` anchors after flush") would flush the live floor-bearing anchor and weaken a landed fail-closed control. Any verification must exclude the current and previous generations, matching the landed guard and its test `prune_owned_tables_preserves_active_and_target_generation_tables` (`phase10.rs`, test module).

**Grounding / reuse.** Shared enumeration (item 4); the drift-reason plumbing (item 2) carries the new dimension to the stage artifact with no additional orchestrator work; flush machinery already exists (`pfctl -a <a> -F all`, `phase10.rs:4818-4823`) and the D2 re-render note (:4825-4841 — flush drops the floor, re-renders if live loopback pins exist) is preserved.

**Existing partial coverage.** `reconcile_exit_nat_residue` (`:4845-4898`) already does residue reconciliation for the NAT/tandem anchors by name (`com.rustynet/nat`, `com.rustynet/tdns_g<N>` via `list_tandem_owned_anchors` :4881) — the pattern to mirror for the DNS-floor anchor family.

**Effort / risk / security / deps.** Effort **M**. Risk: medium (flush-path changes — mitigated as in item 4: strictly increased visibility, prefix-filtered to `com.apple/rustynet_g*`, blind-exit anchor untouched). Security: **strengthens** — removes stranded default-deny mutations (which are fail-closed *direction* but hygiene defects: a stranded floor on a reassigned node can break the node's new posture silently); drift reporting is observe-only. Deps: item 4 (hard), item 2 (carries the drift reason).

**Example — the `DnsFailclosed` case.** Post-investigation cleanup re-applied the floor twice; the check now reports `orphaned_pf_anchors: ["com.apple/rustynet_g2"]` in the same `drift_reasons[]` that item 2 surfaces into the stage artifact — the accumulation is visible in the very first run after it happens, not discovered three ticks later by a hand-run `pfctl -a com.apple -s Anchors`.

---

### 5.10 Item 10 — Additional high-value improvements (batched)

Found while reading; each small, each listed with grounding. Ranked within the batch by leverage.

1. **Why-this-posture trace (S).** Add `posture_inputs: { exit_mode, serve_exit_node }` to `MacosDnsFailclosedReport` (`macos_dns_failclosed.rs:570-583`), filled by the daemon from the same values it passed to `macos_dns_posture` (`daemon.rs:8895`/`:10635`). This dissolves the tautology documented at `:565-569` (posture threaded by caller, never inferred): the report then shows *both* the inputs and the threaded verdict, so a reviewer can independently confirm the derivation. Flows to consumers free via item 2. Linux/Windows siblings get the equivalent field.
2. **Per-stage timing in the ledger row + hang flag (S).** `TimeoutAwareStageRecorder` (`diagnostics.rs:642+`) already tracks stage timing; persist per-stage `duration_secs` into the stages row/stages.tsv and into `run_summary.json`, and flag `possible_hang` when a stage's duration exceeds its historical p95 (history available via `run_history.rs`). Distinguishes "slow" from "hung" at a glance — the distinction §7 of AGENTS.md documents as easy to get wrong.
3. **Clock-skew observation (S).** `collect_failure_diagnostics` (`diagnostics.rs:19-125`) gains a per-node `date -u +%s` sample compared against the orchestrator host clock; skew > 60s is recorded in `summary.json` and cited in failure digests. Rationale: log-correlation and replay/freshness reasoning (anti-replay watermarks) both silently degrade under skew; the motivating investigation lost time to mis-ordered log interpretation before clocks were checked.
4. **Snapshot-diff between runs (M).** `ops vm-lab-diff-snapshots <run_a> <run_b> [--op dns-failclosed]`: joins two runs' item-2 evidence artifacts (or item-1 bundles) and prints per-dimension deltas (`anchors_scanned 0 → 3`, `block_rules_present false → true`, drift_reasons added/removed). Makes "did the fix change the floor?" a one-command answer instead of two artifact reads plus manual comparison. Depends on items 1/2 for artifact availability; pure read-only CLI.
5. **Cross-OS evidence parity assert (S).** Item 1's per-op evidence command lists are declared once per platform; a gate asserts every platform's `DnsFailclosed` (and each other op's) bundle covers the same *logical* dimension set (pf/ruleset, resolver, service pins, daemon state) — so "Linux evidence rich, Windows evidence thin" cannot happen silently. Grounding: the per-OS collect functions already parallel each other (`linux_dns_failclosed.rs:245-282`, macOS snapshot `macos_dns_failclosed.rs:540-554`); the gate pins the parity.

---

## 6. Ranked build order

Ordered by (evidence-class eliminated) × (effort), with dependency-aware grouping.

| Rank | Item | Effort | Why here |
| --- | --- | --- | --- |
| 1 | **5.4 Shared-probe code + divergence gate** | M | Kills the false-evidence class at its root (§2 item 5). Every other item's correctness depends on probes that cannot lie. Worked example lands here. |
| 2 | **5.2 Structured drift into stage result** | S | Nearly free (adapter already parses; stop discarding). Converts *every* future validator failure from a terse string into evidence, independent of item 4. |
| 3 | **5.1 Failure-time evidence bundle** | M | Depends on 4 for probe correctness; reuses the existing pre-cleanup hook. Captures the scene before cleanup destroys it. |
| 4 | **5.8 `get_stage_result`** | M | Artifact-first stage truth + column cross-check; makes P3 mechanized for all consumers. |
| 5 | **5.3 `lab_probe_node`** | M | On-demand structured probes; eliminates hand-rolled probe bugs (§2 item 2). |
| 6 | **5.5 `lab_node_intent`** | M | Kills posture-expectation misdiagnosis (§2, plain-client vs full-tunnel). |
| 7 | **5.7 Launch-gate ergonomics** | S | Small, immediate operator-time win; no dependencies. |
| 8 | **5.9 Anchor/generation hygiene** | M | Requires 4 + 2; real hygiene defect but rarer than ranks 1-3. |
| 9 | **5.6 Hold-on-failure** | M | Highest risk of the set (mutation-lifetime extension); item 1 removes most of its need, so it ships last and stays default-off. |
| 10 | **5.10 batched extras** | S each | Pull items opportunistically; 10.1 (posture trace) rides along with any item-2 work. |

**Top two picks (if only two are built):** **Item 4** and **Item 2**. **[2026-09-04: both are DONE — Item 2 in `1abc7d68`, Item 4's core in `2c10f9d9`; Item 9's prune half partly landed. The highest-leverage REMAINING work is Item 1, Item 3, Item 5, Item 7, Item 8, Item 9's `orphaned_pf_anchors` drift dimension, and Item 10 (Item 4's gate, corrected per the F3 warning, is also open).]** Together they eliminate the two failure classes that cost the most in the motivating investigation — contradictory observers (4) and discarded evidence (2) — at the lowest combined effort, and they are the prerequisites that make items 1, 3, and 9 correct rather than cosmetic.

---

## 7. Verification sketch (per item)

Each item ships with its verification named up front (per AGENTS.md §4's enforcement-point + verification-method rule):

- 5.1: integration test asserting the bundle index lists the expected files for a `DnsFailclosed` failure fixture; negative test: no bundle written when all validators pass.
- 5.2: unit tests on the new `ValidatorReport` return (inconsistent-ok case, multi-object case); artifact schema round-trip test.
- 5.3: MCP contract test (registered name, args validation, argv equals `daemon_probe_for(...).build_argv(...)` output); fail-closed parse test (non-JSON daemon output → `parsed_ok: false`).
- 5.4: the divergence gate itself (§5.4.2) — fixture-based equality of observation paths + the grep tripwire.
- 5.5: derivation table test (all `macos_dns_posture` input combinations, mirroring the existing tests at `phase10.rs:816-840`); ambiguous-run error test.
- 5.6: flag-default-off test; blind-exit rejection test; TTL sweep unit test on a synthetic `cleanup_pending.json`.
- 5.7: gate-message golden test (fully-resolved stub id present); `--from-run` ambiguity refusal test.
- 5.8: column-mismatch surfacing test (synthetic stages.tsv vs artifact disagreement → `matches_artifact: false`).
- 5.9: fixture test (nested orphan anchor appears in enumeration, appears in drift, flush removes it; blind-exit anchor excluded from both).

---

## 8. Cross-references

- Motivating investigation record: commit `427f3c85` ("Log tick 46 addendum: corrected sampler proves floor IS present but check enumeration is blind (root cause A)"), preceded by `864919d9`-family tick logs and the launch-gate remedy record `78a8b513` for `validate_baseline_runtime` pf-floor persistence. *(2026-09-04: the previously cited `864918d9` is not a valid object — the real tick-log commit is `864919d9`.)*
- Ledger hygiene context: QH-07 (quote-aware CSV parsing), QH-37 (column-vs-artifact), QH-39 (mesh-status zero-assertion probes — `build_argv_with_extra_args` comment, `vm_lab/mod.rs:10191` region) in `documents/operations/active/QualityHardeningTodo_2026-07-25.md`.
- Engine context: `documents/operations/active/CrossPlatformRoleParityRefresh_2026-07-23.md` (the Rust `--node` orchestrator is the engine of record; all orchestrator citations here are that engine's code).
- Stage triage ledger: `documents/operations/live_lab_stage_triage.jsonl` and the `ops live-lab-record-stage-patch` surface (`live_lab_stage_triage.rs`).
