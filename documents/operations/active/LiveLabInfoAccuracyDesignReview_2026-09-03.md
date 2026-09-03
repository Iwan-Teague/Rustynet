# Live-Lab Information-Accuracy Design Review — 2026-09-03

**Status:** adversarial review of `LiveLabInfoAccuracyDesign_2026-09-03.md` (docs-only; review artifact, implements nothing).
**Method:** the design was read in full, then its citations were spot-checked against the real code at commit `b06cbaaa` (the design names `427f3c85`; the tree is unchanged between the two for every file cited). Roughly forty `file:line` citations were opened and read, including the full bodies of both divergent observers (`read_pf_dns_block_floor`, `verify_live_pf_dns_floor`), the adapter verdict function (`validator_report_ok`), the pre-cleanup hook wiring, and the MCP tool surface. Empirical verification of macOS `pfctl -s Anchors` behavior on the host was attempted and is **not possible without sudo** (see §3 finding F1) — the behavioral claim rests on the recorded tick-46 lab evidence, which the review treats as authoritative but flags for fixture pinning (§4, M6).
**Verdict in one line:** the design is unusually well grounded — every load-bearing citation checked out — and its central diagnosis is code-confirmed; the required changes are a mandatory redaction contract for the evidence bundle, promoting two "ideally/should" phrases into hard contracts, extending `get_stage_log` instead of adding a fourth read-tool, and one order swap in the build order.

---

## 1. Per-item verdict table

Legend: **G** grounded, **D** duplicative-or-not, **S** security, **F** feasibility. ✅ = no issue; ⚠️ = issue found, fix cited.

| Item | G | D | S | F | Verdict summary |
| --- | --- | --- | --- | --- | --- |
| 5.1 Evidence bundle | ✅ | ✅ extends, not duplicates | ⚠️ S1 | ✅ | Hook point real; redaction is asserted, not enforced — see §3 S1. |
| 5.2 Structured drift | ✅ | ✅ | ✅ | ⚠️ M4 | Exactly as described; merge rule for multi-object reports unspecified. |
| 5.3 `lab_probe_node` | ✅ | ✅ | ✅ | ⚠️ M2 | Shared-parse extraction is "ideally" — must be mandatory; consider dropping `extra_args` in v1. |
| 5.4 Shared probe + gate | ✅ | ✅ | ✅ strengthens | ⚠️ M6, F2 | Root cause code-confirmed; gate fixture must be a real captured transcript, not synthetic. |
| 5.5 `lab_node_intent` | ✅ | ✅ | ✅ | ⚠️ M5 | Most optional tool; `expected_dimensions` is new second-observer logic — must share the evaluator. |
| 5.6 Hold-on-failure | ✅ | ✅ | ⚠️ S2 | ⚠️ F3 | Mitigations right; ordering + malformed-marker failure modes unspecified; second `FinalCleanupStage` call site missed. |
| 5.7 Launch-gate ergonomics | ✅ | ✅ | ✅ | ✅ | Clean; `stub_id` is `:113` not `:112` (trivial). |
| 5.8 `get_stage_result` | ✅ | ⚠️ D1 | ✅ | ⚠️ M3 | Overlaps `get_stage_log`; extend it instead. Column cross-check must be quote-aware (QH-07). |
| 5.9 Anchor hygiene | ✅ | ✅ | ✅ strengthens | ✅ | Depends correctly on 5.4; flush post-condition well specified. |
| 5.10 Batched extras | ✅ | ✅ | ✅ | ✅ | All five grounded; 10.5 (parity gate) is the strongest of the batch. |

---

## 2. Grounding audit (what was verified, where)

Every citation below was opened and read in the real tree. The design's grounding is exceptional: of ~40 checked citations, all but five resolve to within two lines of the named symbol, and none is invented.

**Verified exact (load-bearing):**

- `DaemonProbeOp` enum `vm_lab/mod.rs:10139`, `as_str()` `:10156`, `DaemonProbe` trait `:10173`, `build_argv_with_extra_args` `:10191`, `LinuxDaemonProbe` `:10221`, `WindowsDaemonProbe` `:10257`, `MacosDaemonProbe` `:10284`, `daemon_probe_for` `:10350`, `remote_exec_for` `:10115` — all exact.
- `validator_report_ok` `ssh.rs:894-926`: confirmed **bool-only**; it parses `overall_ok` and `drift_reasons` and discards both after judging; the fail-closed rules in the design (empty/truncated/non-JSON → false; inconsistent ok+drifts → false) match the doc comment at `:874-893` and the negative tests at `:1137-1256` verbatim. The "evidence-discard point" claim is literally true.
- `verify_live_pf_dns_floor` `phase10.rs:4770-4792`: confirmed — reads its **own** in-memory anchor by name (`:4771-4773`), direct `pfctl -a <anchor> -s rules` nested read, fails with `DnsApplyFailed` if either UDP or TCP/53 block rule is missing.
- `read_pf_dns_block_floor` `macos_dns_failclosed.rs:492-507`: confirmed — enumerates via `pfctl -s Anchors` (`:493`) and parses with `parse_pf_anchor_names` (`:328`). Critically, the review checked the alternative hypothesis the design does not explicitly rule out: the check-side filter (`is_rustynet_owned_pf_anchor`, `:315-323`, over `MACOS_RUSTYNET_OWNED_ANCHOR_PREFIXES` `:81-82`) and the daemon-side filter (`owned_anchor_names_from_output`, `phase10.rs:4091-4098`) accept the **same** anchor-name family. The divergence is therefore enumeration-level, not filter-level — exactly as the design claims, and consistent with the recorded tick-46 evidence (commit `427f3c85`: floor present, `anchors_scanned=0`).
- `list_owned_anchors` `phase10.rs:4100-4113` (same top-level enumeration → `prune_owned_tables` `:4817-4823` equally blind), `flush_anchor` blind-exit skip `:4115-4126`, `reconcile_exit_nat_residue` `:4845`, `list_tandem_owned_anchors` `:4442`, `macos_dns_posture` `:801` — all exact.
- Pre-cleanup hook: `native.rs:174` (always-run cleanup contract comment), `:791-805` (closure), `:815-818` (passed into `run_with_observer_and_pre_cleanup_hook`), `:846` (`FinalCleanupStage::new`) — all exact. `collect_failure_diagnostics` `diagnostics.rs:19`, diagnostics dir `:27`, artifacts dir `:40` — exact; and it iterates `ctx.adapters` (`:43-44`), i.e. the platform SSH adapters are already in hand, which makes item 1's wiring feasible exactly as proposed.
- MCP surface `lab_state.rs`: `get_vm_diagnostics` `:4813`, `diagnose_live_lab_failure` `:4833`, `get_run_result` `:4951`, `read_report_artifact` `:4981`, `grep_report` `:4993`, `get_stage_log` `:5006`, `stage_triage_history` `:5100`, dispatch arm `:6187`; and confirmed `lab_probe_node` / `lab_node_intent` / `get_stage_result` **do not exist today** — the design's "no duplicate exists" claims are true.
- Per-OS siblings: `linux_dns_failclosed.rs` evaluate `:85`, build_report `:191`, collect `:245`; `linux_exit_dns_failclosed.rs` writer `:112`, `linux_dns_failclosed_check.json` `:124-126`; `macos_exit_dns_failclosed.rs` writer `:104`, `macos_dns_failclosed_check.json` `:121-123` — all exact.
- Stage-side: `validate_runtime.rs` error string `:158` exact (`{alias}/{op:?}: validation not passed`), `validator_results.json` write `:165-168`, `probe_expectations` `:59`, `OPS` `:92`; `live_lab_stage_triage.rs` `RecordStagePatchConfig` `:143`, executor `:154`, `enforce_launch_gate` `:464`.

**Citation drift (trivial; fix opportunistically if the design is revised):**

| Design says | Actual |
| --- | --- |
| `validator_report_ok` at `ssh.rs:884` | function at `:894` (doc comment starts `:874`) |
| `stub_id` at `live_lab_stage_triage.rs:112` | `:113` |
| `TimeoutAwareStageRecorder` at `diagnostics.rs:642+` | `:636-650` |
| windows check "lib.rs `:89`" | report struct `:126`, evaluate `:136` (`windows_dns_failclosed.rs`) |
| MCP dispatch match `:6053-6187` | `call_tool` match begins `:5121`; the `stage_triage_history` arm is `:6187` |
| `probe_expectations` `:60-67` / `OPS` `:93-98` | `:59` / `:92` |

None of these change any argument; the design's substance is accurately cited.

---

## 3. Confirmed problems

### Security findings

**S1 (top priority) — Item 5.1's "no key material by construction" is an assertion, not a control.** The evidence bundle writes raw command output (`/etc/resolver/` **contents**, daemon **journal tail**, `scutil --dns`, service DNS pins) into the run's report directory, which is committed-adjacent lab evidence that MCP tools (`read_report_artifact`, `grep_report`) happily surface to any agent or human. The repo's own normative bar (AGENTS.md §4, §10.6) treats "never logs secrets" as enforced by gates, not by constructor arguments. Two of the eight listed surfaces are exactly the ones where a future regression (a new daemon log line, a resolver config carrying credentials) would leak silently into every failure report. **Fix (required before item 1 ships):** an explicit redaction contract — (a) an allowlist of observable surfaces per command (paths/log tails are bounded, e.g. journal tail capped in lines), (b) a deny-by-default rule stated in the `EvidenceCommand` type, and (c) a secret-scan gate over `diagnostics/rust-native-failure/evidence/**` in CI, following the existing `secrets_hygiene_gates.sh` pattern. The design's §5.1 security paragraph should cite the gate as the verification method, per the repo's enforcement-point + verification-method rule.

**S2 — Item 5.6's mitigations are right but two failure modes are unspecified.** (a) *Ordering:* the design says a skipped cleanup writes `cleanup_pending.json`, but if the process dies between the skip decision and the write, guests keep pf/DNS mutations with **no** marker for the TTL sweep to find — the worst case is invisible. The marker must be written **before** cleanup is skipped (write-ahead), and the final stage must treat "marker present + cleanup skipped" as the only legal deferral state. (b) *Malformed marker:* the TTL sweep's behavior on a corrupt/partial `cleanup_pending.json` is unspecified — it must fail loud (refuse to proceed, or run full cleanup), never silently clean or silently skip. The blind-exit rejection and the NAT-residue-still-runs rules are correct as written, and the default-off + `vm-lab`-feature containment (RNQ-17) keeps this off shipped paths.

### Correctness / feasibility findings

**F1 — Root cause A's pfctl behavioral claim is not independently verifiable from this host** (`pfctl -s Anchors` needs root; `sudo -n` unavailable). The review accepts the tick-46 recorded evidence, but the design's divergence gate must not encode the behavior as a synthetic assumption — see M6.

**F2 — The divergence-gate grep tripwire fails on day one as specified.** The design's tripwire ("a second `starts_with("com.apple/rustynet_g")`-style filter outside the shared module") collides with two existing, differently-styled implementations: the literal filter at `phase10.rs:4095` and the prefix-const filter at `macos_dns_failclosed.rs:81-82/:315-323`. The refactor itself migrates the phase10 literal into the shared module, which resolves it — but the gate must be authored **as part of** the item-4 refactor with the shared module allowlisted, or the first gate run is red on unchanged code. The design implies this ordering but should state it.

**F3 — Item 5.6 misses the second `FinalCleanupStage::new` call site.** `native.rs:877` constructs the final cleanup stage on the rebuild-only path, in addition to `:846`. A hold flag threaded into only one decision point defers cleanup on one path and not the other — the hold behavior would then depend on which launch mode failed. Both call sites must consult the flag, and the verification sketch (§7) should gain a rebuild-only-path hold test.

**D1 — Item 5.8 overlaps `get_stage_log` more than the design acknowledges.** `get_stage_log` (`lab_state.rs:5006`, handler dispatch `:6187` region) already resolves the run → report dir, locates the stage's row in `state/stages.tsv`, and tails the stage log. `get_stage_result` as specified is `get_stage_log` plus (a) the structured `data` artifact and (b) the `ledger_column` cross-check. The repo's own rule for this situation — stated by the design itself for item 1 ("do not duplicate the generic harvest — extend it") — applies here too: **extend `get_stage_log`** with optional `data` + `ledger_column` fields rather than registering a fourth read-tool that duplicates run/stage resolution. This is also less MCP surface for the ai-agent loop to learn.

### Minor gaps (per-item, one line each)

- **M2 (item 5.3):** "ideally by calling the same function extracted into a shared location" must become **mandatory** — a `lab_probe_node` that re-implements the parse is a third observer of the same verdict and re-creates the §2 failure class in tooling form. Extract `validator_report_ok` (plus its scanner) into a shared module consumed by both `ssh.rs` and the MCP server; the existing negative tests at `ssh.rs:1137-1256` then protect both consumers for free.
- **M3 (item 5.8):** the `ledger_column` cross-check reads `live_lab_node_run_matrix.csv` / `stages.tsv` — both carry quoted comma-bearing fields (the exact QH-07 trap the repo documents in AGENTS.md §12.3). The cross-check must use the quote-aware reader or it inherits the lie it exists to expose.
- **M4 (item 5.2):** `json_object_candidates` can return multiple objects (merged-stderr output is an explicit supported case, test at `ssh.rs:1256`). "last/merged report per node+op" is unspecified — the contract should be: persist **every** parsed object, and mark the one that determined the verdict (the first `overall_ok:false`, or the inconsistent-ok one).
- **M5 (item 5.5):** `expected_dimensions` (`pf_dns_floor: false`, `scoped_resolver: true`, …) is a **new** expectation mapping inside the tool. If the check's evaluator (`evaluate_macos_dns_failclosed_snapshot_for_posture`, `macos_dns_failclosed.rs:611`) and this mapping ever disagree, item 5 has re-created the two-observers bug for expectations. The mapping must be derived from (or share code with) the evaluator, per P2 — the design applies P2 to the observation but not to the expectation.
- **M6 (item 5.4):** the divergence-gate fixture must be a **captured real transcript** (`pfctl -s Anchors` + `pfctl -a com.apple -s Anchors`) from a lab macOS guest, not a synthetic pair. The entire item rests on what real pfctl prints; a synthetic fixture that bakes in the design's assumption would make the gate green while the assumption is wrong. The captured transcript belongs in version control next to the test.
- **M1 (from S1):** redaction contract + secret-scan gate, as specified in §3 S1.

---

## 4. Missing from the design (high-value omissions)

1. **Redaction contract for the evidence bundle** (S1/M1) — the single most important omission. The design's security paragraph asserts safety "by construction"; the repo standard is enforcement + verification. Required.
2. **Mandatory shared-parse extraction** (M2) — "ideally" is not a contract; this is the exact rule the design itself states as P2.
3. **Quote-aware column cross-check** (M3) — item 8's headline feature can silently inherit QH-07.
4. **Posture→expectation sharing** (M5) — item 5's dimensions mapping is unguarded second-observer logic.
5. **Real captured pfctl fixture** (M6) — pins the behavioral crux instead of assuming it.
6. **Hold-on-failure write-ahead marker + malformed-marker fail-loud + second cleanup call site** (S2/F3).
7. **(Optional, recommended) Evidence on the success path too.** Item 1 captures bundles only on failure. Persisting the same per-op check reports on **pass** (the exit-node path already does exactly this — `macos_exit_dns_failclosed.rs:104`, `linux_exit_dns_failclosed.rs:112`) is nearly free after item 2 and is what makes item 10.4's snapshot-diff useful for regression *confirmation* ("did the fix change the floor?") rather than only failure diagnosis. The design's own P5 ("design for the second investigation") argues for it: before/after evidence beats a hole where the passing baseline should be.
8. **(Minor) Schema-version policy.** `schema_version` fields are present throughout (good), but no consumer-side rule states what a reader does on an unexpected version. One sentence — "consumers fail closed on an unrecognized `schema_version`" — completes the format.

---

## 5. Re-ranked build order

The design's dependency analysis is sound; only the top two swap. Everything else keeps its rank.

| Rank | Item | Change vs design | Why |
| --- | --- | --- | --- |
| 1 | **5.2 Structured drift** (S) | ⬆ was 2 | Zero dependencies, S effort, touches only the return shape of a function whose fail-closed tests already exist (`ssh.rs:1137-1256` pin the rules, so the refactor is guarded from both sides). Landing it first means **every** failure during subsequent item-4/5.1 development already carries `drift_reasons[]` — including any regression item 4's flush-path work introduces. The evidence-first order is self-reinforcing. |
| 2 | **5.4 Shared probe + gate** (M) | ⬇ was 1 | Still the root-cause fix and still a top-2 pick; it merely benefits from item 2's evidence being in place while it touches live pf handling (medium risk, per the design's own assessment). |
| 3–10 | 5.1, 5.8, 5.3, 5.5, 5.7, 5.9, 5.6, 5.10 | unchanged | Dependencies preserved: 5.1 needs 5.4; 5.9 needs 5.4+5.2; 5.6 last. 5.8 should be implemented as a `get_stage_log` extension (D1) rather than a new tool, which further reduces its cost. |

**Top two picks: items 5.2 and 5.4 — same set as the design, order swapped.** Justification: they are the only two items that eliminate failure *classes* rather than instances; 5.2 is near-free and de-risks the development of everything after it, while 5.4 kills the false-evidence class at its source. Items 5.1/5.3/5.9 are explicitly dependent on 5.4's correctness (the design says so), and 5.2 feeds 5.1's bundle index and 5.8's `data` artifact — so the pair is the true root of the dependency graph from both directions.

---

## 6. Review limitations

- macOS `pfctl -s Anchors` nested-anchor behavior could not be reproduced on the host (root required; no passwordless sudo) — the behavioral half of root cause A rests on the tick-46 recorded lab evidence, which is consistent with the code divergence but not independently re-proven here (see F1/M6).
- Effort estimates (S/M) were assessed for plausibility, not re-derived; none appeared unrealistic. Item 5.6's M is, if anything, optimistic given F3's second call site and the write-ahead marker requirement — consider calling it M+.
- The review did not execute any lab run or build; it is a read-only artifact review per its mandate.
