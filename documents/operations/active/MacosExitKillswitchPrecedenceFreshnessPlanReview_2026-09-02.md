# macOS Exit Killswitch-Precedence Freshness Plan — Adversarial Review (2026-09-02)

**Subject:** adversarial review of
[`MacosExitKillswitchPrecedenceFreshnessPlan_2026-09-02.md`](./MacosExitKillswitchPrecedenceFreshnessPlan_2026-09-02.md)
(merged `5ab250f1`) — the plan closing follow-up **F2** of
`MacosExitServingAdapterWiringPostMergeReview_2026-09-02.md:215-228`.

**Verdict: ACCEPT-WITH-AMENDMENTS.** Option A (daemon prints the artifact
verbatim on stdout; the adapter captures it fresh; no fixed-path read) is the
right call and is confirmed strictly stronger than Option B. The plan's
substance survives adversarial verification: the stale-pass window is real
exactly as scoped, the fail-closed properties hold, and the offline-testable
core is implementable. Four amendments are required: two line-anchor
corrections (R1), one **wrong substantive claim** about the legacy stage call
sites (R2 — the fixed path has exactly one consumer, so F2 closure needs less
than the plan says), one **dead document reference** (R4), plus one
strengthening change to the `--output` file's fate (R3) and two test
additions (R7). No amendment changes the chosen option.

Docs-only review; no code changed.

---

## 1) Per-anchor verification table

Verdicts: VERIFIED (citation matches current code/docs at this tree,
`b44a8ff6`), STALE (right target, drifted line numbers), WRONG (claim does not
hold against current code/docs).

| # | Plan anchor | Claim | Verdict |
|---|---|---|---|
| 1 | `macos_exit_traffic.rs:571-572` | fixed artifact-path const `MACOS_EXIT_KILLSWITCH_PRECEDENCE_ARTIFACT_PATH` = `/usr/local/var/rustynet/macos_exit_killswitch_precedence.json` | VERIFIED |
| 2 | `macos_exit_traffic.rs:576` | `EXIT_COMMAND_TIMEOUT` = 120 s | VERIFIED |
| 3 | `macos_exit_traffic.rs:602-612` | `capture_exit_snapshot` — daemon prints the lifecycle snapshot JSON verbatim on stdout; adapter never reads a file | VERIFIED |
| 4 | `macos_exit_traffic.rs:602-604` | "design §0 decision 2" doc comment (CLI never re-derives pf parsing) | VERIFIED |
| 5 | `macos_exit_traffic.rs:631-637` | pre-activation-only position doc | VERIFIED (runtime enforcement at `:693-706`) |
| 6 | `macos_exit_traffic.rs:638-672` | `run_killswitch_precedence_baseline` body | VERIFIED |
| 7 | `macos_exit_traffic.rs:642-651` | check script via `daemon_command`; exit-0 required before anything is read | VERIFIED |
| 8 | `macos_exit_traffic.rs:655-663` | `cat` of the fixed path, bytes handed to the hub evaluator | VERIFIED |
| 9 | `macos_exit_traffic.rs:669-671` | post-baseline lifecycle snapshot closes the window | VERIFIED |
| 10 | `ssh.rs:566-574` | non-zero status → `AdapterError::Command` before output is returned | VERIFIED |
| 11 | `ssh.rs:575-579` | success path returns **trimmed** stdout | VERIFIED |
| 12 | `mod.rs:21570-21602` | `evaluate_macos_exit_killswitch_precedence_artifact` | **STALE** — fn is `:21578-21610` |
| 13 | `mod.rs:21576-21598` | shape-only checks (schema_version==1, baseline ok, tampered not-ok + non-zero exit + non-empty reason) | **STALE** — checks are `:21582-21606` |
| 14 | `macos_exit_killswitch_precedence.rs:20` | `…_SCHEMA_VERSION: u32 = 1` | VERIFIED |
| 15 | `macos_exit_killswitch_precedence.rs:44` | `MACOS_NO_ACTIVE_ANCHOR_ERROR` | VERIFIED |
| 16 | `macos_exit_killswitch_precedence.rs:58-64` | report schema is exactly `{schema_version, pf_anchor, baseline_assert, tampered_assert}` — no timestamp/run-id/nonce | VERIFIED |
| 17 | `macos_exit_killswitch_precedence.rs:66-95` | `write_macos_exit_killswitch_precedence_report` | VERIFIED |
| 18 | `macos_exit_killswitch_precedence.rs:79` | `fs::write` happens **before** the asserts are evaluated | VERIFIED |
| 19 | `macos_exit_killswitch_precedence.rs:85-93` | baseline/tamper asserts (and their errors) come **after** the write | VERIFIED |
| 20 | `main.rs:2638-2652` | `run_macos_exit_killswitch_precedence_check_command` fn range | **STALE** — fn spans `:2609-2653` (arg parse `:2613-2639`, write call `:2644-2647`) |
| 21 | `main.rs:2648-2651` | confirmation `println!("macos exit killswitch precedence artifact written to {}")` — the only stdout | VERIFIED |
| 22 | `main.rs:2041-2049` | lifecycle snapshot: `collect_…` then `println!` of pretty JSON verbatim | VERIFIED (println is `:2043-2048`) |
| 23 | `mod.rs:12068` / `:12279` | "legacy stage call sites … read the same fixed path today" | **WRONG** — see R2: `:12272` joins the **per-run** artifact root `report_dir.join("macos_exit_evidence")` (`:11893`), populated this run by capture + collection (`remote_relative_path`, `:13050`); `:12068` is inside the *different* stage `validate_macos_exit_nat_lifecycle` (its own artifact, `:12060`). No legacy site reads `MACOS_EXIT_KILLSWITCH_PRECEDENCE_ARTIFACT_PATH` |
| 24 | review `:206-214` / `:215-228` / `:229-236` / `:253-254` | F1 / F2 / F3 / "considered, no defect" bullets | VERIFIED (F2's wording, mitigations list, and the `:253-254` gating bullet match; note `:253-254` itself carries the same `:12068`/`:12279` line drift, not a substantive error there) |
| 25 | `stage/exit_nat_lifecycle_validation.rs:97-111` | reactivation (restart → `activate_exit_serving` → `assert_exit_actively_serving`) as the live vehicle | VERIFIED |
| 26 | `ReleaseReadinessGuardrails.md:33-34`, `:49-51` | gate must fail on missing/stale/malformed/unbound input; pre-existing files are not proof | VERIFIED verbatim |
| 27 | `SecurityMinimumBar.md:134-136`, `:240-245` | 7-day tighten-only freshness window; control 8 "Data-plane leak prevention" incl. "authenticated, replay-protected, freshness-bounded" endpoint-hint state | VERIFIED |
| 28 | `Requirements.md:182` | anti-replay / bounded lifetime / nonce / clock-skew clause (enrollment/auth flows) | VERIFIED verbatim |
| 29 | `CrossPlatformRoleParityRefresh_2026-07-23.md:117-134` | CP-1 environmental triage (macOS two_hop 8/8 fail) | VERIFIED |
| 30 | `CrossNetworkLiveLabPrerequisitesChecklist.md:57` | "already flags guest-clock sensitivity" | **WRONG** — the file does not exist anywhere under `documents/`; the only reference to that name in the entire docs tree is the plan's own citation (R4) |

Anchor score: 26 VERIFIED / 3 STALE / 2 WRONG. The STALE/WRONG items do not
change any decision; R2 changes one scope statement.

## 2) Numbered findings and amendment text

### R1 (must-fix, anchors) — evaluator and command-fn line anchors drifted

GLM-authored line numbers drifted ~8 lines on the two biggest files. Content
claims are otherwise accurate at the new lines.

**Amendment (plan §1.1, §1.2, §3, §4, §5):** replace

- `evaluate_macos_exit_killswitch_precedence_artifact` …
  (`mod.rs:21570-21602`) → `… (`mod.rs:21578-21610`)`
- shape-only checks (`mod.rs:21576-21598`) → (`mod.rs:21582-21606`)
- `run_macos_exit_killswitch_precedence_check_command`
  (`crates/rustynetd/src/main.rs:2638-2652`) → `… (`main.rs:2609-2653`)`
- snapshot verbatim print (`main.rs:2041-2049`) → tighten to the println at
  `main.rs:2043-2048`

### R2 (must-fix, substantive) — the legacy stage call sites do NOT read the fixed path; F2 closure needs less than §5 claims

Plan §5: "The legacy stage call sites (`mod.rs:12068`, `:12279`; review
`:253-254`) read the same fixed path today and carry the same emergent
binding: migrating them to stdout capture is in-scope for this fix (same
defect, same repair) and is the only way the 'stale file' leg fully closes."

That is wrong on both halves:

- Stage 9 `validate_macos_exit_killswitch_precedence` (`mod.rs:12244-12313`)
  evaluates `macos_exit_artifact_root.join("macos_exit_killswitch_precedence.json")`
  (`:12272`), where `macos_exit_artifact_root = report_dir.join("macos_exit_evidence")`
  (`:11893`) — a **per-run** report directory. The file it reads was captured
  *this run* by the capture script and pulled back via the collection spec
  (`remote_relative_path`, `:13050`), and the stage is gated on mesh-join and
  capture success before evaluating (`:12255-12270`). A leftover file from a
  prior run cannot occupy a fresh run's report dir (the orchestrator refuses a
  non-empty report dir).
- `mod.rs:12068` is inside the *different* stage
  `validate_macos_exit_nat_lifecycle` (NAT-lifecycle artifact, `:12060`) — not
  a precedence call site at all.

Consequence: `MACOS_EXIT_KILLSWITCH_PRECEDENCE_ARTIFACT_PATH` has **exactly
one consumer** — the adapter's `cat` (`macos_exit_traffic.rs:655-663`). Once
Option A drops that read, the stale-file leg closes completely; migrating the
legacy stage is neither required nor the "only way" anything closes. The
legacy stage's own evaluation contract (absent → Skip, run-local capture) is a
separate concern outside F2 and should not be folded in silently.

**Amendment (plan §5, replace the sentence block):**

> The fixed path's only consumer is the adapter's `cat`
> (`macos_exit_traffic.rs:655-663`). The legacy Stage 9
> (`validate_macos_exit_killswitch_precedence`, `mod.rs:12244-12313`) reads a
> different input: the per-run captured copy under
> `report_dir/macos_exit_evidence` (`mod.rs:11893`, `:12272`, collected via
> `:13050`), gated on mesh-join and capture success, so it does not carry the
> fixed-path stale-file defect and is NOT migrated by this fix. Dropping the
> adapter's `cat` therefore closes the stale-file leg completely on its own;
> the legacy stage's absent→Skip posture is recorded here as out of F2 scope.

### R3 (should-fix, strengthening) — decide the fixed-path file's fate explicitly: prefer the adapter stops passing `--output`

Option A removes the file from the *trust* path but the plan keeps the
adapter passing `--output`, so the daemon still writes the fixed-path file
every run and the stale-artifact side-channel persists on the guest
(verified: no `remove_file`/cleanup anywhere in the adapter or capture
script; single writer caller `main.rs:2644`). That is acceptable only if it is
unread — but the strictest-secure-practical default (AGENTS.md §2) is to stop
creating hazard material at all. The on-guest file at that fixed path has no
remaining consumer (R2), and the capture-script forensics path already uses
per-run directories.

**Amendment (plan §3 Option A + §4 adapter side):**

> The adapter's check invocation **drops the `--output` argument entirely**:
> `daemon_command` is called with no extra args, so no file is created at
> `MACOS_EXIT_KILLSWITCH_PRECEDENCE_ARTIFACT_PATH` on the lab path and the
> stale-artifact side-channel is eliminated rather than merely unread. The
> daemon keeps `--output` as an optional operator/forensics feature of the
> subcommand. `MACOS_EXIT_KILLSWITCH_PRECEDENCE_ARTIFACT_PATH`
> (`macos_exit_traffic.rs:571-572`) is deleted with the `cat`.
> Test 5 then pins BOTH: no `cat` of the path AND no `--output` in the
> baseline command list.

If the plan prefers to keep on-guest forensics at the fixed path, the
fallback amendment is: keep `--output`, and state explicitly "no code path
reads the fixed path after this change; test 5 pins the absence of any read;
the file persists as trusted-by-nobody forensics." The preferred amendment is
the stronger one.

### R4 (must-fix, dead reference) — `CrossNetworkLiveLabPrerequisitesChecklist.md` does not exist

Plan §3 (Option B) cites `CrossNetworkLiveLabPrerequisitesChecklist.md:57`
for "already flags guest-clock sensitivity". No file of that name exists
anywhere under `documents/`; the only occurrence of the name in the docs tree
is the plan's own citation. This violates the repo rule against dead links
(AGENTS.md §5/§6). The clock-skew argument stands on its own — Option B is
rejected for the file-trust reason regardless.

**Amendment (plan §3, Option B bullet):** delete the
"`(`CrossNetworkLiveLabPrerequisitesChecklist.md:57` already flags
guest-clock sensitivity)`" parenthetical, or replace it with a pointer to a
document that exists (the freshness-window pattern is stated in
`SecurityMinimumBar.md:134-136`).

### R5 (verified, no amendment) — the stale-pass window is real exactly as scoped, and today's mitigations leave it open

Confirmed against the code:

- The window's precondition (a) holds: the fixed path is written every
  completed run (`precedence.rs:79`), nothing deletes it, and nothing in the
  adapter or capture scripts cleans it.
- Precondition (b) is genuinely emergent, not contractual: the single
  function `write_macos_exit_killswitch_precedence_report` orders
  `fs::write` (`:79`) before the assert-driven errors (`:85-93`), with no test
  pinning that ordering, and the adapter verifies nothing about the daemon's
  version before trusting bytes at the path. A refactor returning `Ok` before
  the write, or a stale guest binary, re-arms the window. The plan's
  "closed today by accident of ordering, re-armed by one unreviewed daemon
  edit or one stale guest binary" is accurate.
- Precondition (c) holds: the evaluator (`mod.rs:21582-21606`) is shape-only —
  any prior pass artifact passes it forever.
- The three mitigations are correctly characterized: exit-0-before-read
  (`ssh.rs:566-574`) closes only the "daemon errored, file remains" leg;
  the `:653-654` comment does overclaim the stale half (absence errors —
  `cat` of a missing file exits non-zero through the same guard — presence
  does not); pre-activation-only (`macos_exit_traffic.rs:693-706`) bounds the
  consumer's state, not the artifact's age. Severity call (§2: lab-only,
  vm-lab-feature-gated, fix before predicate-flip evidence) is consistent
  with `ReleaseReadinessGuardrails.md:49-51` and RNQ-17.

### R6 (verified, no amendment) — Option A is the strictest-secure choice; freshness is structural; fail-closed properties hold; stdout risks are controlled

- **Strictly stronger than B:** A removes the file from the trust path, so
  there is nothing whose freshness would need asserting. B's binding is
  metadata inside the untrusted artifact; once a nonce is threaded
  end-to-end the timestamp is redundant and adds a clock-skew failure mode.
  A is also smaller (no schema change, no evaluator recency arithmetic). The
  rejection of B is sound in both directions.
- **Freshness without any freshness field:** correct. `ssh::run_remote`
  (`ssh.rs:552-580`) returns the stdout of the process executed *by this
  invocation*; there is no persistent channel or cached read. The adapter can
  only ever possess bytes the just-run check printed. No timestamp, no nonce,
  no clock policy needed — capture-on-this-invocation *is* the freshness
  binding.
- **Fail-closed properties confirmed:** non-zero exit →
  `AdapterError::Command` at `ssh.rs:566-574` before anything is evaluated;
  empty/whitespace stdout and confirmation-line-only stdout → the planned
  strict extraction errors; foreign/short payload (e.g. a stale daemon
  printing only the old confirmation line) → extraction error; a
  schema-mismatched document that somehow reaches it → the evaluator's parse
  and shape checks error (`mod.rs:21582-21606`). No fallback branch is
  proposed — correct under the one-hardened-path rule.
- **New-risk audit of stdout transport, all bounded:**
  - *Interleaving:* the check command's stdout today carries exactly one line
    (`main.rs:2648-2651`), which moves to stderr; the JSON is a single
    `println!` of one document. The daemon's pfctl invocations capture child
    output in-process (`precedence.rs:460-474`), never inheriting stdio, so
    no tool chatter can interleave into the daemon's stdout.
  - *Truncation:* `run_remote_inner` reads the child's full stdout as one
    buffer; the artifact is four fixed fields (two nested assert objects) —
    kilobytes, far under any buffer/timeout concern, and `EXIT_COMMAND_TIMEOUT`
    (120 s) still bounds the whole sequence.
  - *Mixed output:* `ssh.rs:575-579` end-trims only, safe for a JSON
    document; a guest-side MOTD/shell noise line would make the strict
    whole-document extraction fail loudly — which is the correct behavior,
    and the plan already names its unmeasured likelihood honestly (§6).

### R7 (should-add, tests) — the offline core is implementable; add two cases

All five named tests are implementable offline as specified: the extraction
helper is pure string→Result; the sequence's command list is built offline
(closure-driven precedent, `macos_exit_traffic.rs:674-706`), so the structural
no-`cat` pin (test 5) is feasible with the runtime-assembled-needle pattern
already proven by
`anchor_restore_uses_the_audited_helper_not_a_local_temp_file`
(`precedence.rs:496-528`); the daemon-side `precedence_check_stdout_is_report_json`
is implementable by having the command build its two output strings and
assert on them (the command fn is already unit-tested for arg parsing at
`main.rs:5812-5823`, and the non-macos `collect_…` path
(`precedence.rs:443-457`) yields a parseable synthetic report so the test runs
on Linux CI). Two additions:

1. **`precedence_stdout_capture_rejects_truncated_json`** (extend test 4 or
   add): a captured document that is valid JSON *prefix* but truncated
   mid-object must error at extraction — pin that the helper extracts
   whole-document only, never a lenient prefix. (Today the evaluator would
   catch a truncated doc at `serde_json::from_str`, but the pin belongs at
   the new boundary the fix introduces.)
2. **Leftover-file-ignored pin** (with R3 accepted, folded into test 5):
   assert the baseline command list contains neither a `cat` of the fixed
   path nor `--output` — structurally proving a leftover file is neither read
   nor re-created by the sequence. If R3's fallback (keep `--output`) is
   taken instead, add the explicit companion assertion that no read of
   `MACOS_EXIT_KILLSWITCH_PRECEDENCE_ARTIFACT_PATH` exists anywhere in the
   module source.

## 3) Collision surface (task question 6) — confirmed clean, one note to add

- **`3f0be0c1` (exit-adapter A2 wiring):** owns the same function
  (`run_killswitch_precedence_baseline`) and file. The plan already mandates
  serial landing against F1's `:23` attribute edit (§5). Confirmed — the
  plan's serial-landing requirement stands; no further conflict.
- **In-flight macOS DNS three-state fix:** owns `macos_dns_failclosed.rs`,
  `macos_exit_dns_failclosed.rs`, and the phase10 DNS stages — verified no
  planned edit touches those. One verified edge the plan should record:
  `macos_dns_failclosed.rs:60-62` imports
  `MACOS_RUSTYNET_ANCHOR_PREFIX` and `validate_pf_anchor_name` **from the
  precedence module**. The plan's daemon-side change (write fn returns the
  encoded string; no schema change; single caller `main.rs:2644`) touches
  neither imported item, so there is no overlap — but §5 should name the
  dependency so a future rename inside the precedence module does not
  silently break the DNS fix's build.

**Amendment (plan §5, add):**

> Note: `macos_dns_failclosed.rs:60-62` (in-flight macOS DNS three-state fix)
> imports `MACOS_RUSTYNET_ANCHOR_PREFIX` and `validate_pf_anchor_name` from
> `macos_exit_killswitch_precedence.rs`. This fix renames neither; keep it
> that way while the DNS fix is in flight. Files are disjoint, so the two
> changes may land in either order.

## 4) Considered, no defect

- **Exit-0⇒fresh-write ordering** (`precedence.rs:79` write before `:85-93`
  asserts): real today; the plan treats it as emergent rather than a contract
  and does not rely on it — correct posture.
- **Missing-file errors:** `cat` of the absent path exits non-zero and fails
  through the same `ssh.rs:566-574` guard — the "missing errors" half of the
  `:653-654` comment is true; only the "stale" half overclaims, as the plan
  says.
- **`sudo -n` stdout cleanliness:** `pfctl` child output is captured
  in-process by `run_pfctl` (`precedence.rs:460-474`), never inherited, so
  the daemon's own stdout stays a clean single document. Not named in the
  plan; verified here and now recorded.
- **Non-macos collect path** (`precedence.rs:443-457`) builds a synthetic
  report with empty rules; if ever invoked it would fail the baseline assert
  and exit non-zero through the same error path — no silent-pass leg added by
  the stdout change.
- **Post-baseline A2 restore snapshot** (`macos_exit_traffic.rs:669-671`) is
  independent of the capture mechanism (its own subcommand, already
  verbatim-on-stdout) — unaffected by Option A beyond sequence ordering,
  which the plan keeps.
- **Evaluator offline accept test** already exists
  (`mod.rs:47500-47516`, `evaluate_macos_exit_killswitch_precedence_artifact_accepts_reviewed_payload`),
  grounding the plan's claim that the evaluator is unchanged and offline-testable.
- **Severity placement** (§2: Low-Med, lab tooling, fix before
  predicate-flip evidence, not a product fail-closed violation): consistent
  with SecurityMinimumBar control 8's actual text, `Requirements.md:182`'s
  enrollment/auth scope, RNQ-17's feature gating, and
  `ReleaseReadinessGuardrails.md:49-51`.
- **CP-1 gating honesty** (§6: a green live proof additionally needs the CP-1
  networking work): matches `CrossPlatformRoleParityRefresh_2026-07-23.md:117-134`.

## 5) Disposition

Apply R1-R4 and the §5 note before implementation; R3 and R7 are strongly
recommended and cost nothing (R3 shrinks the diff; R7 adds two test cases).
With those applied, proceed to the implementation commit per the plan's own
plan → review → impl requirement (§5 of the plan).
