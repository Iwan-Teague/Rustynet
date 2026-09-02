# Windows Clock-Skew Hardening Plan — preflight gate remediation (R2)

**Date:** 2026-09-02
**Scope:** Docs-only Phase A+B plan for RCA finding **F4** (`documents/operations/active/WindowsNodeParityRootCauseAnalysis_2026-09-02.md:228`, status OPEN). No code changes are made by this document; every code reference below is a *proposal* with an offline-testable core.
**Trigger evidence run:** `livelab-1785005557-b7667cce46db` (commit `b7667cce46dbe2891b65f3be68b0dd0d809e7fe2`, clean tree, 2026-07-25T18:52:19Z→18:52:37Z, report dir `/home/ubuntu-server/lab-reports/winnat-20260725T185101Z` on `ubuntu-kvm-1`) failed at stage `preflight` with a **3602 s guest clock skew** on `windows-x86-1` (role: exit).

---

## 1) Root-cause options for a whole-hour (3602 s) skew

The recorded failure is verbatim (`documents/operations/live_lab_node_stage_results.csv` rows for `windows-x86-1` **and** `linux-x86-client-1`, since `preflight` is a topology-scoped stage that reports once per failed node; also `documents/operations/live_lab_stage_triage.jsonl:50`):

```
windows-x86-1: guest clock skew is 3602s (maximum 90s; host=1785005541, guest=1785001939)
```

Host − guest = **+3602 s**: the guest was *behind* the host by one hour plus two seconds. The prior triage verdict already flagged the signature (`documents/operations/active/WindowsNodeBootstrapTriageVerdict_2026-08-28.md:80-83`): *"generic guest NTP drift of exactly 3602 s, i.e. one hour plus two seconds, the signature of a timezone/DST offset rather than clock wander."* The RCA records the same observation (`WindowsNodeParityRootCauseAnalysis_2026-09-02.md:150`) and lists the current guest clocks as an unknown (`:313` — 3602 is **one sample**).

Candidate causes, with what each implies:

| # | Cause | Mechanism | Signature | Offline-verifiable? |
|---|-------|-----------|-----------|---------------------|
| 1 | **RTC set to localtime vs UTC mismatch** | Windows by default keeps the hardware RTC in *localtime*; if the hypervisor wrote UTC into the RTC (or `RealTimeIsUniversal` was set and then undone), the guest boots one hour fast/slow depending on TZ. Symmetric failure exists on Linux guests booted with the opposite RTC convention. | Whole-hour offset **plus a small residual** (the +2 s) | Partially: the *shape* (within tolerance of a multiple of 3600) is verifiable offline from recorded pairs (see §3); *which* convention is wrong needs a live probe |
| 2 | **Guest TZ mis-set (or DST transition not applied)** | Guest OS timezone is wrong or a DST change was not applied; the RTC is fine but interpretation shifts by ±1 h | Identical to #1 — a clean ±3600 s quantum | No — indistinguishable from #1 offline; needs live probe (`tzutil /g` on Windows, `timedatectl` on Linux) |
| 3 | **w32time enabled but no NTP egress** | The guest is NAT-only (windows-x86-1 bootstrapped at `192.168.121.108` behind libvirt NAT on `ubuntu-kvm-1`); `w32tm` cannot reach its configured peers, so the clock free-runs from the last RTC sync | This produces **seconds-scale wander**, not whole-hour offsets | The *absence of NTP egress* is a standing lab property (documented; NAT-only guest), but it explains only the residual +2 s, not the 3600 |
| 4 | **Hypervisor RTC offset / paused-guest clock lag** | QEMU guests that were paused or restored without clock resync lag by the pause duration | Arbitrary magnitude, not quantized to 3600 | No — needs live probe of host/guest clocks after a fresh boot |

**Working hypothesis (to be confirmed live, never assumed):** causes #1/#2 dominate — a one-hour TZ/RTC-convention error — with #3 explaining the small residual. This matters because the *remedy differs*: a TZ/RTC-convention fix is a one-shot deterministic correction, while a free-running clock needs a persistent time source (which the NAT-only guest may lack — see §3's Windows remedy evaluation).

### What a live probe must capture (blocked, see §5)

- Windows guest: `w32tm /query /status`, `w32tm /query /source`, `tzutil /g`, registry `RealTimeIsUniversal` value, and the raw `DateTimeOffset::UtcNow` the gate already reads.
- Linux guest: `timedatectl status` (NTP sync flag, TZ) — precedent for reading this read-only already exists at `crates/rustynet-cli/src/vm_lab/mod.rs:26254`.
- Host: `date +%s` at the same instant, to reproduce the 3602 pairing and check whether it recurs across fresh boots (is it a *stateful* RTC value or a *deterministic* convention error? A convention error reproduces exactly ±3600 ± drift every boot; a stale RTC value does not).

---

## 2) Why the preflight gate must stay fail-closed (and what "self-heal" may mean here)

The 90 s gate (`MAX_LAB_CLOCK_SKEW_SECS`, `crates/rustynet-cli/src/vm_lab/orchestrator/stage/preflight.rs:9`) is not a cosmetic lab nicety. Clock correctness is load-bearing for the security state a lab run distributes and verifies:

- **Signed-bundle freshness.** Membership bundles are quorum-signed and freshness-checked; `SecurityMinimumBar.md:136` requires rejecting signed state *"future-dated beyond clock-skew tolerance"* and that *"the epoch does not regress"*. A guest whose clock is an hour behind accepts (or should accept) bundles an hour stale without noticing; a guest an hour ahead rejects everything fresh and — worse — makes *its own* signed assertions future-dated for peers. The replay watermark protection that makes rollback impossible is a *time-ordered* mechanism.
- **Replay/anti-replay clauses.** `Requirements.md:182`: *"Enforce anti-replay protections for enrollment/auth flows with bounded token lifetime, nonce/state checks, and **strict clock-skew policy**."* `Requirements.md:202`: traversal updates are *"replay-protected, and freshness-bounded; unsigned or stale … rejected fail-closed."* The word "strict" in the requirements is exactly this gate.
- **Parity mandate.** `Requirements.md:146` requires Windows to prove *"signed-state verify, anti-replay"* live. A preflight that lets a clock-skewed Windows node into a run would make any downstream Windows signed-state pass **untrustworthy** — the parity evidence would be contaminated, not merely delayed.

Therefore the gate's current fail behavior is correct and is **not** to be relaxed. The current implementation already fails closed correctly: `validate_clock_skew` (`preflight.rs:55-64`) returns `Err` on `abs_diff > max`, transport retries are bounded (`retry_transient`, `preflight.rs:26-45`, 3 attempts × 750 ms per `:19-20`), and the stage maps the error to `StageOutcome::Failed`. `parse_remote_unix_time` (`:47-53`) fails on unparseable output rather than defaulting.

What F4 actually asks for is not softening but **remediation with the same fail-closed discipline**:

1. **Explicit** — a diagnosis/classification step (§3) that produces a machine-checkable verdict, never a silent auto-fix.
2. **Logged** — the verdict, chosen remedy, and both before/after clock readings are recorded in the stage artifact so the run matrix row is self-describing.
3. **Bounded** — exactly **one** remediation attempt per preflight execution (no retry loops that mask a broken time source by hammering it).
4. **ONE path** — no runtime fallback between remedy strategies; the per-platform remedy is selected deterministically by the classifier (§3), not by try/catch cascade (§3 constraint: one hardened execution path).
5. **Re-measured through the SAME gate** — after remediation, the clock probe runs again through the identical `validate_clock_skew` path; if skew still exceeds the maximum, the stage **still fails**, now with richer error text. Self-heal can only convert "fail with no explanation" into "fail with a diagnosis", never "pass despite skew".

This mirrors the repo's standard fail-closed pattern (AGENTS.md §10.1/§10.5): verify-then-apply, and default-deny on missing/invalid state — an unparseable clock reading is treated as an error, never as "assume fine".

---

## 3) The offline-testable core: `propose_clock_remediation` (pure function)

**Proposal** — add to `crates/rustynet-cli/src/vm_lab/orchestrator/stage/preflight.rs`:

```rust
pub(crate) enum ClockVerdict {
    WithinTolerance,                       // |host-guest| <= max_skew_secs
    HourOffset { offset_hours: i64 },      // skew within ±30s of a nonzero multiple of 3600
    GenericDrift { skew_secs: i64 },       // beyond tolerance, no hour quantum
    Unparseable { detail: String },        // guest time string failed to parse
}

pub(crate) fn propose_clock_remediation(
    host_unix: u64,
    guest_unix: u64,
    max_skew_secs: u64,
    platform: Platform,                    // the same platform enum the probe loop already uses
) -> Result<ClockVerdict, String>          // Err = remediation refused (skew still > max)
```

Classification rules (all pure, all unit-testable offline):

- **Parse boundary first:** if the guest time string cannot be parsed (`parse_remote_unix_time`, `preflight.rs:47-53`), return `Unparseable` — never guess (§2 discipline; §10.1 fail-closed).
- **Within tolerance:** `host_unix.abs_diff(guest_unix) <= max_skew_secs` → `WithinTolerance`, no remedy.
- **Hour-offset consistency:** skew `s` (computed as `host - guest`, signed) is *hour-quantized* iff `|(|s| − round(|s|/3600)·3600)| ≤ 30`. `round(|s|/3600) ≥ 1` → `HourOffset { offset_hours: sign(s)·round(|s|/3600) }`. The 30 s band admits the observed +2 s residual on 3602 while rejecting, e.g., 1800 (half an hour) or 7200±200.
- **Everything else** → `GenericDrift { skew_secs }`.
- **Never returns `Ok` when the skew exceeds `max`**: the function classifies, but the *gate* still fails; remediation is a separate, explicitly-enabled step (§4). This is the negative-invariant unit test below.

### Per-platform remedy text (selected deterministically — ONE path, no fallback cascade)

The security-relevant evaluation: the guest is **NAT-only with no guaranteed NTP egress** (§1 cause #3). A remedy whose correctness depends on reaching an NTP server is *not* a hardened single path in this lab — it silently does nothing when egress is absent, which is a soft-fail masquerading as a fix.

| Platform | Candidate | Verdict for this lab |
|---|---|---|
| Windows | `w32tm /resync` | **Rejected as sole remedy**: requires reachable NTP source; on the NAT-only guest it exits success-or-noise with no clock change. Acceptable only *after* egress exists. |
| Windows | PowerShell `Set-Date` with host-supplied target, rendered argv-only via the existing `PowerShellScript` seam (`from_call_argv` / `from_single_value`, used by `windows_install.rs` / `windows_traffic.rs`) | **Chosen**: deterministic, no egress, argv-only (no shell construction from untrusted values), matches the privileged-boundary rules (§4). For `HourOffset`, additionally correct the *convention* (set TZ via `tzutil /s UTC` argv, or fix `RealTimeIsUniversal`) — because `Set-Date` alone cures the symptom and the next reboot reintroduces the hour. |
| Linux | `timedatectl set-ntp true` / `chronyc makestep` | Same egress objection; offline fallback is `timedatectl set-time @<host_unix>` (argv-only, sudo). Read-only precedent: `vm_lab/mod.rs:26254`. |
| macOS | `sntp`/`systemsetup -setusingnetworktime` | Same objection; offline fallback `systemsetup -setdate` (requires admin; render argv-only). |

Exact argv strings are **deliberately not finalized in this docs-only phase** — they land with the implementation, where each is pinned by the unit tests below and by a live-probe confirmation (§5, §7). What *is* fixed now is the selection rule: **for `HourOffset`, fix convention first, then set the clock; for `GenericDrift`, set the clock once from the host reading; for `Unparseable`, no remedy — fail.**

### Named unit tests (all offline, in `preflight.rs` `#[cfg(test)]`)

1. `clock_verdict_passes_within_max` — skew == max → `WithinTolerance`/`Ok`.
2. `clock_verdict_fails_beyond_max` — skew == max+1 → not `WithinTolerance` (extends the existing 90-pass/89-fail edge coverage in `remote_clock_parser_and_skew_check_fail_closed`).
3. `clock_verdict_classifies_hour_offset` — 3602 s and −3602 s → `HourOffset { ±1 }`; 7195 s → `HourOffset { 2 }` (inside band).
4. `clock_verdict_rejects_non_hour_quantum` — 1800 s, 7205 s (>band) → `GenericDrift`.
5. `clock_verdict_negative_unparseable` — unparseable guest string → `Unparseable`, never a remedy.
6. `clock_verdict_negative_never_ok_when_skew_exceeds_max` — for **every** variant at skew > max, the combined classify-then-gate path returns the failure; classification never upgrades a failing skew to a pass.

These extend, and must not regress, the existing tests (`preflight_passes_with_exit_node_and_writable_dir`, `preflight_fails_with_no_exit_node`, `remote_clock_parser_and_skew_check_fail_closed`, the three `retry_transient` tests).

---

## 4) Optional guarded self-heal (flag-gated, one-shot, fail-closed)

**Proposal** — an orchestrator-level flag, **default OFF** (absent flag ⇒ behavior identical to today's fail-only gate):

- Scope: preflight stage only; elected in the same way other orchestrate flags are (CLI flag on the `--node` orchestrate path).
- Flow: probe → classify (§3) → if flag OFF: fail exactly as today. If flag ON **and** verdict is `HourOffset`/`GenericDrift`: execute the deterministic per-platform remedy **once**, log it (tracing + stage artifact), re-probe, re-validate through `validate_clock_skew`; still skewed ⇒ `StageOutcome::Failed` with the enriched message (original skew, verdict, remedy attempted, post-remedy skew). `Unparseable` and `WithinTolerance` never trigger a remedy.
- Boundedness: one attempt per stage execution; the retry budget (`CLOCK_PROBE_ATTEMPTS`, `preflight.rs:19-20`) remains transport-only.
- Recording: the stage artifact gains a `clock_remediation` block (verdict, remedy argv, before/after readings, re-check result) so the run-matrix row and triage JSONL carry the full story — a remediation that "worked" without recorded evidence is treated as not having happened.
- Non-goal: self-heal is **not** a licence to mask a broken lab. A guest that needs remediation on every run is a lab defect (§1); the repeated-remediation pattern must be visible in the artifacts, not hidden by automation.

---

## 5) Live-lab proof shape (currently blocked — recorded honestly)

- **Intended run:** `windows-x86-1` in the `exit` role, driven from `ubuntu-kvm-1` (the host that ran both July-25 runs, report dirs `winnat-20260725T185101Z` / `winnat-20260725T190000Z`), reproducing the failing topology; then a re-run with the remediation flag ON demonstrating: fail-with-diagnosis (flag OFF) → remedy + pass (flag ON, clock actually corrected).
- **Blocker:** `ubuntu-kvm-1` is **currently unreachable** (management-plane outage at time of writing), so no live evidence can be produced in this phase. The alternative guest `windows-utm-1` is equally blocked until remote management is restored.
- **Acceptance artifact line (when unblocked):** a `live_lab_node_stage_results.csv` row for the remediation-enabled run whose `preflight` stage shows the enriched fail message (flag-OFF run) and a `pass` with the `clock_remediation` artifact block (flag-ON run), attributed to the implementation commit — plus the matching `live_lab_stage_triage.jsonl` stub. Per §12.3 of AGENTS.md, the pass claim is taken from the stage artifact's own status + data block, never from the CSV column alone.

**Until that run exists, F4 remains OPEN and this plan makes no claim of remediation efficacy on real guests.**

---

## 6) Collisions with in-flight work

Verified by grep at the time of writing:

- **`preflight.rs` has no other in-flight owner.** F4 is the only open finding that names it (RCA `:228`; code path cited as `stage/preflight.rs:55-64`). F6 (PowerShell CLIXML `Count` leak in *cleanup* artifact collection — visible in the same run's `cleanup` row: *"The property 'Count' cannot be found on this object"* `PropertyNotFoundStrict`) is adjacent but a different file/stage; its fix (commit `45d27d56`) does not touch preflight.
- **No existing remediation commands to collide with:** the repo has no `w32tm`/`Set-Date`/`sntp`/`chronyc` usage anywhere in `vm_lab`; the only time-related guest interaction is the read-only `timedatectl status` diagnostic at `crates/rustynet-cli/src/vm_lab/mod.rs:26254`.
- Other F-fix commits (F2 `7bb72149`, F3 `03483da6`, F5 `003d5edc`) are in unrelated areas (per RCA §:228 table) and do not overlap the preflight stage.

---

## 7) Explicit unknowns / needs-live-probe list

1. **Which of §1's causes actually produced the 3602 s** — requires the §1 live probe bundle (`w32tm`/`tzutil`/`RealTimeIsUniversal`/`timedatectl` + simultaneous host reading). 3602 is one sample from one night (RCA `:313`).
2. **Whether the offset reproduces across fresh boots** (deterministic convention error) or was a one-off RTC state.
3. **Current clock health of both Windows guests** (`windows-x86-1` and `windows-utm-1`) — unknown while hosts are unreachable.
4. **Whether NTP egress exists for the guest at all** under the NAT topology — determines whether `w32tm`-style remedies are viable *post*-convention-fix or whether the offline `Set-Date` path remains the only hardened remedy.
5. **Exact argv text for each platform remedy** — deliberately deferred to implementation, pinned by §3's tests + live probe; this document intentionally does not finalize them.
6. **Whether the linux-x86-client-1 duplicate failure row** (topology-scoped stage reports the windows error against both nodes) is the desired reporting shape or a separate small reporting defect to note when implementing §3 — observable offline from the existing CSV (`:12505`/`:12556`), needs an implementation-phase decision, not new evidence.

---

## Relationship to other ledgers

- Supersedes nothing; **operationalizes F4** from `WindowsNodeParityRootCauseAnalysis_2026-09-02.md` (which stays the finding-of-record until the §5 run lands, at which point F4 moves to fixed-with-evidence there).
- Consistent with `WindowsNodeBootstrapTriageVerdict_2026-08-28.md` §runs table (skew = run #4) and the `LiveLabStagePassLikelihood_Windows_2026-09-01.md` mentions of the same failure.
