# Adversarial Review: WindowsClockSkewHardeningPlan_2026-09-02

- **Date:** 2026-09-02
- **Status:** Review COMPLETE — verdict below.
- **Verdict:** **ACCEPT-WITH-AMENDMENTS**
- **Subject:** `documents/operations/active/WindowsClockSkewHardeningPlan_2026-09-02.md` — the R2 remediation for the OPEN finding F4 (`WindowsNodeParityRootCauseAnalysis_2026-09-02.md:228`) against `crates/rustynet-cli/src/vm_lab/orchestrator/stage/preflight.rs`.
- **Scope of this review:** docs-only adversarial verification of the plan. No code was changed. Every anchor and clause citation in the plan was checked against the current tree, the classifier design was attacked, the security posture of the host-clock self-heal was checked against the trust-freshness code it leans on, the fail-closed discipline was hole-hunted, and the PowerShell/argv seam claims were traced to the constructors that would render them.

## 1. Verdict summary

**ACCEPT-WITH-AMENDMENTS.** The plan's load-bearing claims all hold:

- Every file:line anchor the plan cites (preflight gate constants, trust clauses, RCA finding, triage verdict, seam constructors) is **VERIFIED** accurate against the current tree (per-anchor table in §4).
- The ±30 s hour-quantum band is sound and **cannot upgrade a failing skew to a pass**: the >90 s tolerance check (:83) strictly precedes quantization (:84), and the nearest whole-hour quanta above the band boundary are ≥3530 s away, so anything that reaches the classifier already fails; the `clock_verdict_negative_never_ok_when_skew_exceeds_max` test (:108) pins it.
- The self-heal's host-clock-as-time-source is **not a downgrade** of any control (§3): the guest daemon verifies bundle freshness against its OWN local clock, and the orchestrator host already mints and distributes the signed bundles — aligning the verifier clock to the mint clock is what the lab already trusts. One strict rule must be added: the remedy target must be a FRESH host reading captured inside the remediation attempt, never the probe-time reading (TOCTOU) and never a computed offset (finding A-4).
- The remedy is renderable through the existing argv-only seams (`PowerShellScript::from_call_argv`) with **no format!-built shell**, but it requires a NEW per-class timestamp validator in `validated_args.rs` — the plan must name that class as an architectural deliverable, not defer it as "argv detail" (finding A-9).

Eight amendments required before implementation; none change the plan's direction, one corrects a test/example that contradicts the plan's own band definition (A-5), one removes an unreachable classifier variant (A-2), and the strictest-secure rule change is A-1 (remedy only hour-quantized signatures; generic drift gets diagnosis, never mutation).

## 2. Numbered findings

Severity: HIGH = must fix before implementation; MEDIUM = must fix, small; LOW = should fix. Amendment text is exact and copy-paste applicable to the plan doc.

### A-1 — MEDIUM — GenericDrift must not be remediated; it is an unknown-cause signature

**Evidence:** plan :99 and :119 route `GenericDrift` to a clock-set remedy. But GenericDrift is precisely the *unknown cause* bucket: RCA hypothesis #3 (w32time with no NTP egress — seconds wander) and #4 (pause/restore lag — arbitrary) both land there, and neither is fixed by setting the clock once. A pause-lag guest will re-drift after the next pause, silently "eating" one remediation attempt and masking the real cause. The plan's own discipline 4 ("ONE path, deterministic remedy selection") argues against guessing.

**Also the security-strictest reading (§3 of this review):** an unquantized drift is the only drift shape whose cause is unproven; mutating a guest clock whose error mechanism is unknown is the one direction this plan cannot bound. Hour-quantized skew has a *characterized* cause (RTC-localtime / TZ convention, RCA :150, TriageVerdict :80-83); generic drift does not.

**Amendment (replace the GenericDrift row of the :99 selection rule and the :119 flow):**

> `GenericDrift` → **diagnose-only, no mutation.** The stage fails exactly as today with an enriched failure message (measured skew, verdict, captured probe artifacts) and no remedy attempt. `HourOffset` → convention fix first, then the one clock-set attempt. Only hour-quantized signatures may be remediated.

**Add test:** `clock_verdict_generic_drift_gets_no_remedy` — GenericDrift input never yields a remedy plan.

### A-2 — MEDIUM — the `Unparseable` variant is unreachable in the classifier as specified

**Evidence:** plan :66-69 defines `ClockVerdict::Unparseable{detail}` and :82 says "parse boundary first → return Unparseable." But the classifier signature (:63 area) is `propose_clock_remediation(host_unix: u64, guest_unix: u64, max_skew_secs: u64, platform: Platform) -> Result<ClockVerdict, String>` — it takes **already-parsed** u64s. Parse failure happens upstream in `execute()`: `parse_remote_unix_time` (preflight.rs:47-53) errors → the stage fails with `'{alias}: {err}'` before any classifier runs. No input to the pure function can be unparseable, so the variant is dead code and the named test `clock_verdict_negative_unparseable` (:107) is **unimplementable as written**.

**Amendment (either):**

> (a) Drop `Unparseable` from `ClockVerdict`. Parse failure stays an execute()-level failure; the `clock_remediation` artifact block records parse failure with verdict `ParseFailed` at the stage layer, not in the classifier enum. Delete test `clock_verdict_negative_unparseable`.

> (b) Keep the variant but change the signature to accept the raw probe bytes/strings, making parse genuinely the first classification boundary.

Option (a) is preferred — it keeps the pure core pure and matches the existing fail-closed parse path.

### A-3 — MEDIUM — sign convention must be pinned: `offset_hours` positive = guest BEHIND host

**Evidence:** `validate_clock_skew` (preflight.rs:55-64) is symmetric (`host_unix.abs_diff(guest_unix)`); the classifier takes signed `s = host_unix − guest_unix`. The two are consistent only if the sign convention is documented and the remedy never uses signed arithmetic off the probe. The observed live case (host=1785005541 > guest=1785001939, plan trigger section) is `s = +3602` → guest behind → `HourOffset{offset_hours: +1}` under this convention; test :105's `−3602 → {−1}` is the mirrored input pair and is fine **provided the test states the (host, guest) argument ordering explicitly**.

**Amendment (add to the :82-85 classify rules):**

> Sign convention: `s = host_unix − guest_unix`; `s > 0` means the guest clock is BEHIND. `HourOffset.offset_hours` carries this sign. The remedy target is always a fresh host reading captured in the attempt (see A-4) — never `guest + offset_hours * 3600` or any offset arithmetic on the probe reading.

### A-4 — MEDIUM — TOCTOU: the remedy must capture a FRESH host reading, not the probe-time one

**Evidence:** plan :99 says the remedy sets the clock "from the host reading" but does not say *which* reading. The probe reading may be minutes old at remediation time. Worse, a *computed or reused past/future* target is the only way this remedy could set a guest clock BACKWARD relative to true time — and backward-set is the one direction with security consequence (it could revive a near-expired bundle that the guest's freshness check would now accept; §3). Setting the guest to the host's genuine current time is always corrective.

**Amendment (add to :99 and the :121 artifact block):**

> The remedy target is `SystemTime::now()` captured **inside the remediation attempt**, immediately before rendering the command argv — never the probe-time `host_unix` and never a value computed from the probe. The `clock_remediation` artifact block records both `probe_host_unix` and `remedy_target_host_unix` so the gap is auditable.

**Add test:** remedy-path unit test asserting the rendered target equals a host reading taken at remedy time (freshly-captured), not the probe input.

### A-5 — MEDIUM (defect in the plan text) — test example :106 contradicts the band definition :84

**Evidence:** plan :84 defines hour-quantized as `|(|s| − round(|s|/3600)·3600)| ≤ 30`. Plan :106 expects `7205 → GenericDrift`. But `|7205 − 7200| = 5 ≤ 30` → the band rule classifies 7205 as `HourOffset{2}`. The test as specified would fail against the band as specified — the plan is internally inconsistent and the test would force a band change nobody intends.

**Amendment (replace the :106 example):**

> `clock_verdict_rejects_non_hour_quantum`: `1800` (exactly between quanta) and `7240` (`|7240 − 7200| = 40 > 30`) both classify `GenericDrift`.

### A-6 — MEDIUM — the flag-OFF path needs a byte-identity test, and must emit NO `clock_remediation` block

**Evidence:** plan :116 (default OFF) and :119 (OFF ⇒ fail as today) are correct, but nothing pins the OFF path. Without a test, a refactor can silently change the OFF-path failure text (the exact string live-lab triage greps for: `guest clock skew is {skew}s (maximum {max}s; host={host}, guest={guest})`) or emit a partial artifact block, making OFF runs look remediated.

**Amendment (add to the :103-108 test list):**

> `preflight_failure_text_identical_with_flag_off`: with the flag OFF, a skewed node produces the exact pre-change failure text and the stage artifact contains **no** `clock_remediation` block.

### A-7 — LOW — band boundary inclusivity is undocumented

**Evidence:** `≤ 30` is inclusive; `3630` (residual exactly +30) classifies `HourOffset{1}` while `3631` does not. The plan never states this, and boundary values are where regressions hide.

**Amendment (add to :84 and the test list):**

> The residual band is **inclusive** (`|residual| ≤ 30`). Add boundary tests: `3630 → HourOffset{1}`, `3631 → GenericDrift`.

### A-8 — LOW — plan :11 wording over-claims per-node reporting; the duplicate row is intended run-scoped attribution

**Evidence:** plan :11 says the preflight failure "reports once per failed node." The stage is `StageFanout::Once` (run-scoped; registry `live_lab_stage_registry.rs:459-488` — criterion `Pre` + `Once` ⇒ `run_scoped`, and such stages must NEVER be written into per-OS `{platform}_stage_*` columns; measured problem documented at :472-480: preflight carries `logical: Some("bootstrap")` with `PlatformRule::AllPlatforms`). The duplicate `linux-x86-client-1-bootstrap` row beside `windows-x86-1-bootstrap` (CSV :12505 / :12556, same run_id/commit b7667cce46db) is the run-matrix attribution layer stamping a run-scoped failure onto every in-scope node identity — **intended by current code**, with the run-level verdict carried by `overall_result`/`first_failed_stage`. The pin test `run_scoped_matches_orchestrator_fanout_for_every_dispatched_pre_stage` (`live_lab_run_matrix.rs:3815-3834`, test at :3827) documents exactly this split (PerNode `Pre` = genuine per-node verdict; `Once` `Pre` = lab-wide precondition).

**Verdict on Q6:** intended-by-code, misleading-at-attribution-level; a small **separate reporting defect** (forward-only fix in the run-matrix writer), **not a blocker for this plan**.

**Amendment (correct :11):**

> The preflight stage is run-scoped (`StageFanout::Once`); the run-matrix attributes its failure to each in-scope node identity in the per-node ledger, which is why both `windows-x86-1` and `linux-x86-client-1` carry a `-bootstrap` failure row for the trigger run. Attribution is a separate, forward-only reporting cleanup (W-FIX-3 `run_scoped` mechanism, `live_lab_stage_registry.rs:459-488`); it does not block this plan.

### A-9 — MEDIUM — the plan must NAME the timestamp validator class; it is architecture, not argv detail

**Evidence:** plan :99 defers the exact remedy argv. Fine. But rendering `Set-Date -DateTime <target>` through the seam requires `PowerShellScript::from_call_argv` (`windows_install.rs:150`) whose argv elements are `ValidatedArg` — and `validated_args.rs` (module doc :1-8: THE ONE home for per-class validators; existing: `node_id` :90, `connection_user` :108, `validate_ip_arg` :357, `validate_utun_name` :363, `validate_windows_path` :369) has **no timestamp class**. `PowerShellScript` has deliberately NO whole-script String constructor (:169-173) so a `format!`-built command string is impossible by construction; `from_single_value` (:134) and `from_call_argv` both quote every element. So the seam holds — but only if the digits-only validator exists. Deferring its existence would force an ad-hoc string push into the argv, which the seam type system exists to prevent.

**Amendment (add a deliverable to §3):**

> A new per-class validator `validate_unix_seconds_arg` in `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/validated_args.rs` (digits-only ASCII, no leading `+`/`-`, plausible unix-seconds range) gates the timestamp argument before any command string is built, per the module's own placement rule (:1-8). Windows remedy renders via `PowerShellScript::from_call_argv(label, &[ValidatedArg])`; the Linux remedy renders as argv elements (`timedatectl`, `set-time`, `@<secs>`) through `run_argv` — no shell, no `format!`.

## 3. Security analysis of the host-clock self-heal (Q3)

**Question:** is trusting the orchestrator host's clock as the time source a downgrade of any control, or equivalent to what the lab already trusts?

**Answer: not a downgrade — it is the trust the lab already exercises.** Chain of evidence:

1. **The guest verifies freshness against its OWN clock.** `crates/rustynetd/src/daemon.rs:570` `DEFAULT_SIGNED_STATE_MAX_CLOCK_SKEW_SECS: u64 = 300`; future-dated bundles are rejected against local `now` at daemon.rs:14016 (`record.updated_at_unix > now.saturating_add(trust_policy.max_clock_skew_secs)` → reject) and the same shape at :14851/:15302/:15629/:15897 (bundle `generated_at_unix` vs `now + max skew`). The domain crate's tolerance lives in `rustynet-control/src/lib.rs:95` (`clock_skew_tolerance_secs`, default 90 at :102), used in the replay window at :537/:542/:572 and expiry at :1964-1968.
2. **The host already mints the time that matters.** The orchestrator host creates the membership bundles with their `generated_at`/epoch fields and distributes them in setup. The guest's freshness check compares *host-authored timestamps* against the *guest's local clock*. A 3602 s skew means that comparison is currently nonsense — the gate correctly refuses. Setting the guest clock from the host does not inject a new trust anchor; it repairs the comparator so the EXISTING host-authored timestamps become checkable again.
3. **Lab env is explicitly allowed to widen windows** via `RUSTYNET_TRAVERSAL_MAX_AGE_SECS` / `RUSTYNET_AUTO_TUNNEL_MAX_AGE_SECS` (daemon.rs:340 `DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS = 300`; lab raises both to 86400 — `ops_e2e.rs:260-261/716-719/798-836/911-913`). A preflight clock repair that makes the guest agree with real time only ever *tightens* what those wide lab windows accept.
4. **Direction analysis:** setting the guest AHEAD of true time is what the fault already is, and is rejected by every freshness check (future-dated). Setting it BEHIND true time is the only consequential direction — it could revive a bundle within `expires_at + tolerance` that should have expired. A remedy that sets the guest to the host's genuine current time is corrective, not reviving; the finding A-4 rule (fresh reading captured in the attempt, never a computed target) is what keeps it that way.
5. **Blast radius:** preflight is `vm-lab`-feature-gated tooling (RNQ-17) — none of this is a production path. The production analogue (NTP) is explicitly NOT what this plan does.

**Could a remediation move a guest clock in a way that lets a stale/replayed bundle validate?** Only if it set the guest clock *backward past a bundle's generation time that had already been locally rejected as future-dated*. That requires a deliberately computed past target — which the A-4 amendment (fresh host-now, captured in the attempt, recorded in the artifact) forecloses. With A-4 in place: no.

**Must the remedy be refused when drift is NOT hour-quantized?** Yes — finding A-1. Unquantized drift has unproven cause; the strictest secure rule is: **remedy only the hour-quantized signature (HourOffset); GenericDrift fails with diagnosis and never mutates the clock.** This also matches the evidence base: every observed skewed Windows row is hour-quantized (RCA :150 "3602 s ≈ exactly one hour"; TriageVerdict :80-83), so A-1 costs nothing today while bounding the unknown.

## 4. Per-anchor verification table

| Plan citation | Target | Verdict |
| --- | --- | --- |
| MAX_LAB_CLOCK_SKEW_SECS = 90 at preflight.rs:9 | :9 `const MAX_LAB_CLOCK_SKEW_SECS: u64 = 90;` | VERIFIED |
| CLOCK_PROBE_ATTEMPTS :19 | :19 (=3, with `CLOCK_PROBE_RETRY_BACKOFF=750ms` :20) | VERIFIED |
| parse_remote_unix_time :47-53 | :47-53 (UTF-8 + trim + `parse::<u64>`) | VERIFIED |
| validate_clock_skew ~:55-64 | :55-64, `abs_diff` symmetric, exact error text `guest clock skew is {skew}s (maximum {max}s; host={host}, guest={guest})` | VERIFIED |
| retry_transient :26-45 | :26-45 (transport-only; `.expect` at :44 justified by attempts≥1 invariant) | VERIFIED |
| SecurityMinimumBar.md:136 (future-dated / epoch no regress) | :136 verbatim | VERIFIED |
| Requirements.md:146 (Windows parity, signed-state + anti-replay) | :146 | VERIFIED |
| Requirements.md:182 (anti-replay + strict clock-skew) | :182 | VERIFIED |
| Requirements.md:202 (freshness-bounded traversal) | :202 | VERIFIED |
| RCA F4 OPEN at :228 | :228 — F4 \| 3602s \| OPEN | VERIFIED |
| TriageVerdict:80-83 (TZ/DST signature) | :80-83 verbatim ("generic guest NTP drift of exactly 3602 s ... signature of a timezone/DST offset") | VERIFIED |
| RCA :150 ("≈ exactly one hour") / :313 ("one sample") | :150 / :313 | VERIFIED |
| triage JSONL:50 (preflight stub, run livelab-1785005557-b7667cce46db) | :50 | VERIFIED |
| PowerShellScript::from_call_argv / from_single_value | windows_install.rs:150 / :134; no String ctor by design :169-173; base64-over-SSH :198-199 | VERIFIED |
| timedatectl read-only precedent | vm_lab/mod.rs:26254 (`timedatectl status`, read-only) | VERIFIED |
| w32tm rejection premise (NAT-only, no NTP egress) | plan §1/§3; consistent with trigger run topology | VERIFIED (as stated; live confirmation still an open unknown per plan §7) |
| duplicate linux-x86-client-1 row (CSV :12505/:12556) | both rows present, same run_id/commit b7667cce46db; mechanism = run_scoped, live_lab_stage_registry.rs:459-488 (esp. :472-480), pin test live_lab_run_matrix.rs:3815-3834 | VERIFIED — but see A-8 (wording) |
| plan test example :106 `7205 → GenericDrift` | contradicts band :84 (`\|7205−7200\|=5 ≤ 30` → HourOffset{2}) | **WRONG** — A-5 |
| plan :82 "parse boundary first → Unparseable" | unreachable given u64 signature | **WRONG** — A-2 |
| plan :99/:119 GenericDrift remediated | security-strictest rule says no | **AMEND** — A-1 |

No STALE anchors found: every citation that exists in the tree resolves to the exact line range claimed.

## 5. Answers to the posed review questions (summary)

1. **Citations:** all VERIFIED except two plan-internal inconsistencies (A-2, A-5) — table above.
2. **Classifier:** band is sound; the tolerance check strictly precedes quantization, so no classification can upgrade a failing skew to a pass (test :108 pins it). `Unparseable` is unreachable as specified (A-2). Sign convention consistent with `abs_diff` once pinned as guest-behind-positive (A-3). Test example 7205 is wrong (A-5).
3. **Security:** host-clock-as-source is not a downgrade (§3); stale/replayed-bundle revival is foreclosed by the A-4 fresh-reading rule; GenericDrift must be refused (A-1).
4. **Fail-closed discipline:** no fail-reads-as-pass hole found; the one gap is unpinned flag-OFF behavior (A-6). One-attempt (:53), same-gate re-measure (:54/:119), default-OFF (:116), artifact block (:121) are all correctly designed.
5. **Argv-only seam:** yes — `PowerShellScript::from_call_argv` renders it with no format!-built shell; the required validator class is `validate_unix_seconds_arg` in `validated_args.rs` (A-9).
6. **Duplicate row:** intended run-scoped attribution, separate forward-only reporting defect, not a blocker (A-8).
7. **Named tests:** implementable except :107 (A-2) and :106's 7205 case (A-5); missing: flag-OFF byte-identity (A-6), GenericDrift-no-remedy (A-1), band boundary (A-7), fresh-reading-at-remedy (A-4).

## 6. Considered, no defect

- **Gate stays fail-closed (:46):** the 90 s constant and error text are untouched by the plan; the heal path only ever converts a fail into fail-with-diagnosis or a pass via a genuine re-measure.
- **w32tm /resync rejected as sole remedy (:94):** justified — guest is NAT-only with no NTP egress; a resync with no reachable source is a no-op that would consume the one attempt.
- **ONE attempt (:53):** bounded mutation; re-probe after; second skew fails with enriched message.
- **Re-measure through the SAME gate (:54):** the only legitimate fail→pass transition, and it goes through `validate_clock_skew` itself, not a classifier shortcut.
- **Flag default OFF (:116):** no behavior change ships unobserved.
- **`clock_remediation` artifact block (:121):** makes a silent heal impossible; the stage report carries verdict + argv + before/after + re-check.
- **No collisions (:140-142):** F6 cleanup CLIXML fix (45d27d56), F2 (7bb72149), F3 (03483da6), F5 (003d5edc) all touch different files.
- **`PowerShellScript` has no whole-script String constructor (:169-173):** a format!-built command is impossible by construction — the strongest seam guarantee available.
- **Existing test `preflight_passes_with_exit_node_and_writable_dir` asserts `Passed OR Failed`:** a weak existing assert (it cannot distinguish the skew failure from other failures), but it cannot regress under this plan and tightening it is out of scope here.
- **RNQ-17 feature gating:** all of preflight is default-off in the shipped binary; this work cannot affect production paths.
- **`retry_transient` `.expect` at :44:** justified by the attempts≥1 clamp invariant; transport-only retry does not mask a genuine skew.

## 7. What must land before implementation

1. A-5 test example fix (7240, not 7205) — the plan is internally inconsistent today.
2. A-2 resolution (prefer: drop `Unparseable`).
3. A-1 strict rule (HourOffset-only remediation).
4. A-4 fresh-reading rule + artifact fields.
5. A-3 sign-convention sentence.
6. A-6 flag-OFF byte-identity test added to the named test list.
7. A-7 boundary tests.
8. A-9 named validator class as a plan deliverable.
9. A-8 wording correction on :11 (plus the separate reporting-defect note).

Live-lab proof (plan §5) remains blocked on host reachability and is unchanged by this review; F4 stays OPEN until the CSV row + `clock_remediation` block + triage JSONL evidence exists.
