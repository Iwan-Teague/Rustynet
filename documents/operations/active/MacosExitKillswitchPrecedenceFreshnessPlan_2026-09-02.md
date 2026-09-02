# macOS Exit Killswitch-Precedence Artifact Freshness Plan (2026-09-02)

**Status:** IMPLEMENTED (Option A, with the adversarial review's amendments
applied — see
[`MacosExitKillswitchPrecedenceFreshnessPlanReview_2026-09-02.md`](./MacosExitKillswitchPrecedenceFreshnessPlanReview_2026-09-02.md);
R1-R4 and the §5 note applied, R3 accepted in its preferred form, R7 accepted).
Daemon half: `e52d1cae` (the check subcommand prints the encoded report
verbatim on stdout, confirmation on stderr, `--output` now optional —
stdout-only mode leaves no artifact file). Adapter half: `b5de5a3c` (the
baseline captures the check's stdout, `extract_precedence_report_stdout`
is the fail-closed boundary, the fixed-path constant and the `cat` read are
deleted, no `--output` is passed, hub evaluator rejects non-object payloads
by name). Offline tests: daemon `precedence_check_stdout_is_report_json` +
`precedence_check_without_output_confirms_stdout_only_mode`; adapter
`precedence_stdout_capture_accepts_fresh_verbatim_json`,
`..._rejects_empty_stdout`, `..._rejects_confirmation_line_only`,
`..._rejects_leading_or_trailing_text_around_json`,
`..._rejects_truncated_json` (R7), and
`killswitch_precedence_baseline_sequence_has_no_artifact_path_read` (no
`--output`, no read step, no module reference to the deleted fixed path —
the leftover-file-ignored pin). Live proof still owed by the macOS exit
cell per §6 (CP-1-gated).

Closes follow-up **F2 (Low-Med — evidence freshness)** of
[`MacosExitServingAdapterWiringPostMergeReview_2026-09-02.md`](./MacosExitServingAdapterWiringPostMergeReview_2026-09-02.md).
The original finding: the macOS exit killswitch-precedence artifact has no
freshness binding, so a leftover valid-shape file at the fixed path could be
read as a fresh pass if the daemon ever exited 0 without rewriting it.

**Chosen fix: Option A — the daemon prints the artifact verbatim on stdout and
the adapter captures it fresh (capture-over-SSH, no fixed-path read at all).**
Option B (schema `captured_at_unix` + per-run nonce, evaluator asserts
recency/nonce-match) is specified and rejected below as the weaker binding.

---

## 1) The exact fail-open window

### 1.1 What the adapter trusts today

`run_killswitch_precedence_baseline`
(`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_exit_traffic.rs:638-672`)
consumes the precedence evidence in three steps:

1. Run the daemon's mutating experiment via SSH and require exit 0
   (`:642-651`; the exit-0 guard itself is `ssh.rs:566-574` — a non-zero
   status becomes `AdapterError::Command` before anything is read back).
2. `cat` the artifact off the guest's filesystem at the compile-time
   fixed path `MACOS_EXIT_KILLSWITCH_PRECEDENCE_ARTIFACT_PATH`
   (`:571-572`, `:655-663`) and hand the bytes to the hub evaluator
   `evaluate_macos_exit_killswitch_precedence_artifact`
   (`crates/rustynet-cli/src/vm_lab/mod.rs:21570-21602`).
3. Close the experiment window with a post-baseline lifecycle snapshot
   proving the anchor restore (`:669-671`).

The evaluator is **shape-only**: it checks `schema_version == 1`, that
`baseline_assert.overall_ok` is true, that `tampered_assert.overall_ok`
is false with a non-zero `exit_code` and a non-empty `reason`
(`mod.rs:21576-21598`). It has **no timestamp, no run id, no nonce, and
no notion of when the bytes were captured**. The schema itself carries
nothing to bind it to a run:
`MacosExitKillswitchPrecedenceReport` is exactly
`{schema_version, pf_anchor, baseline_assert, tampered_assert}`
(`crates/rustynetd/src/macos_exit_killswitch_precedence.rs:58-64`;
`MACOS_EXIT_KILLSWITCH_PRECEDENCE_SCHEMA_VERSION = 1` at `:20`). This is
the review's F2 core claim, verified verbatim at
`MacosExitServingAdapterWiringPostMergeReview_2026-09-02.md:215-228`.

### 1.2 The precise stale-pass sequence

A STALE artifact is read as a fresh pass when all of the following hold:

- **(a) A valid-shape artifact exists at the fixed path from a previous
  run.** The path `/usr/local/var/rustynet/macos_exit_killswitch_precedence.json`
  persists on the guest across orchestrator runs — nothing deletes it,
  and every completed run rewrites the same location
  (`write_macos_exit_killswitch_precedence_report`,
  `macos_exit_killswitch_precedence.rs:66-95`).
- **(b) The current run's check command exits 0 without rewriting that
  file.** Under *today's* daemon this cannot happen through the known
  path — `write_macos_exit_killswitch_precedence_report` writes the file
  (`:79`) *before* it evaluates the baseline/tamper asserts and returns
  any error (`:85-93`), so every exit-0 pass implies a fresh write, and
  every pre-write failure (e.g. `MACOS_NO_ACTIVE_ANCHOR_ERROR`, `:44`)
  exits non-zero and is caught by the `ssh.rs:566-574` guard. **But that
  exit-0⇒fresh-write implication is emergent from the internal ordering
  of one function, not a contract**: no test pins it, and it silently
  breaks under (i) any refactor that returns `Ok` before the write, or
  (ii) version skew — a guest running an older/partially-installed
  daemon binary whose check command can exit 0 without writing (the
  orchestrator ships source, but `install-release` on a guest can leave
  a stale binary behind; nothing in the adapter verifies the daemon's
  version before trusting its file).
- **(c) The bytes then pass the shape-only evaluator.** Any leftover
  artifact from any prior successful run does, by construction — it was
  written by the same schema version and passed the same asserts when it
  was fresh.

So the honest statement: **under today's committed code the window is
closed by accident of ordering, and one unreviewed daemon edit or one
stale guest binary re-arms it.** The adapter never verifies it is
reading evidence from *this* run — it reads a filesystem location, not a
process output. That is exactly the evidence-binding principle the repo
already states for release gates: "Pre-existing files are not proof. A
stale bundle file or report file must not be treated as release
evidence unless the current gate execution regenerated it"
(`documents/operations/ReleaseReadinessGuardrails.md:49-51`; the same
document requires the gate to fail on any input "missing, stale,
malformed, or not bound to the current commit/evidence state",
`:33-34`).

A secondary window exists even with a perfectly behaving daemon: the
bytes sit at a world-predictable path between the write (`:79`) and the
`cat` (`:663`), so anything on the guest that rewrites that file in that
gap is invisible to the evaluator — the adapter cannot distinguish
"what the experiment wrote" from "what is at the path now". Low
likelihood in the lab, but it is the same missing-binding defect: trust
is placed in a file, not in a received message.

### 1.3 Why today's mitigations do not fully close it

- **exit-0-before-read (`ssh.rs:566-574`)** — guarantees the *command*
  succeeded, not that the *file* is from this run. It closes the
  "daemon errored but file exists" leg only; it does nothing about the
  version-skew and refactor legs in §1.2(b).
- **missing-file-errors (`:653-654`)** — the comment's own claim ("a
  missing, stale, unparseable, or foreign-schema artifact is an error")
  **overclaims the stale half**, as the review notes: absence errors,
  presence does not. A stale file is exactly a *present* file.
- **pre-activation-only (`MacosExitActivationSequence::precedence_baseline`,
  `macos_exit_traffic.rs:631-637`)** — bounds *when* the evidence is
  consumed (once, before activation is attempted) and is good defense
  against replaying the experiment against an already-activated exit,
  but it constrains the consumer's state, not the artifact's age.

## 2) Security precedence call — product defect or lab-only residue?

**Verdict: acceptable lab-only residue today, with a mandatory freshness
binding before the macOS exit cell's evidence is allowed to stand — i.e.
fix it as lab tooling hardening, not as a product fail-closed violation,
but fix it before predicate-flip evidence is recorded.** Reasoning by
clause:

- **Not a product dataplane violation.** The artifact producer is a
  verifier subcommand, not an enforcement point: the daemon's killswitch
  enforcement and the experiment's snapshot→flush→assert→restore
  mechanics are unchanged by this defect. SecurityMinimumBar §3 control
  8 ("Data-plane leak prevention",
  `documents/SecurityMinimumBar.md:240-245`) requires tunnel fail-close
  behavior in protected-routing modes and — in the same control —
  "authenticated, replay-protected, freshness-bounded" state for
  endpoint hints; the *product* paths carrying that freshness duty
  (membership attestations, traversal hints, watermarks) are elsewhere
  and already bounded (e.g. §6.B's 7-day tighten-only freshness window,
  `SecurityMinimumBar.md:134-136`). `Requirements.md:182` ("Enforce
  anti-replay protections … bounded token lifetime, nonce/state checks,
  and strict clock-skew policy") is likewise an enrollment/auth-flow
  requirement, not a lab-artifact requirement. F2 does not violate
  either clause as written — but both clauses state the *house pattern*
  the evidence layer should follow, and the artifact currently does not.
- **It is vm-lab-feature-gated tooling.** The whole consumer side lives
  under the default-off `vm-lab` cargo feature (RNQ-17; AGENTS.md §11.2:
  "the shipped release binary carries none of it"). No shipped binary
  reads or trusts this artifact. That caps the severity at Low-Med and
  keeps it out of the release-blocking product-defect class.
- **But the lab evidence ledger is the project's proof-of-work.** The
  `--node` run matrix is the engine of record for cross-platform parity
  (AGENTS.md §2), and `ReleaseReadinessGuardrails.md:49-51` explicitly
  forbids treating pre-existing files as evidence. A check that can, in
  principle, pass on residue is a check that can mint a false
  `exit`-role parity proof on macOS — exactly the cell this campaign is
  trying to prove. The strictest-secure-practical-default rule (AGENTS.md
  §2: "If ambiguity exists, choose the strictest secure practical
  default") therefore binds the *lab tooling* to the freshness standard
  even though the product is not violated.

## 3) Two candidate fixes, strictest chosen

### Option A (CHOSEN) — daemon prints the artifact verbatim on stdout; the adapter captures it fresh

Mirror the lifecycle-snapshot pattern that already exists three files
away: `capture_exit_snapshot` runs
`rustynetd macos-exit-nat-lifecycle-snapshot` and the daemon prints the
JSON document to stdout verbatim (`main.rs:2041-2049`); the adapter
never reads a file (`macos_exit_traffic.rs:602-612`). Apply the same
shape to the precedence check: the check command prints the report JSON
to stdout (its current stdout carries only the confirmation line
"macos exit killswitch precedence artifact written to {path}",
`main.rs:2648-2651` — that line moves to stderr), keeps writing the
`--output` file for on-guest forensics/legacy consumers, and the adapter
drops the `cat` entirely, evaluating the captured stdout.

- Removes trust-in-a-file **entirely**: the adapter can only ever
  possess bytes the just-executed process emitted on the channel it just
  read. A leftover file at any path is structurally unreachable. No
  clock, no clock-skew policy, no nonce plumbing.
- Less code than B: no schema change, no producer clock read, no
  adapter→daemon nonce argument, no evaluator recency arithmetic. Two
  small edits (daemon stdout, adapter capture) + a pure extraction
  helper.
- Fits the existing daemon-prints-verbatim pattern (§0 decision 2 of the
  adapter design, cited at `macos_exit_traffic.rs:602-604`) and the
  SecurityMinimumBar house pattern of freshness-bounded state — here
  freshness is structural, not asserted.

### Option B (REJECTED as weaker) — schema freshness binding

Add `captured_at_unix: u64` (and/or a per-run nonce echoed by the
adapter, e.g. via a `--run-nonce` validated arg) to
`MacosExitKillswitchPrecedenceReport`
(`macos_exit_killswitch_precedence.rs:58-64`), assert recency or
nonce-match in `evaluate_macos_exit_killswitch_precedence_artifact`
(`mod.rs:21570-21602`).

- Still trusts a file: the binding is *metadata inside the untrusted
  artifact*. A fresh-timestamped file is still not proven to be from
  this run's experiment unless the nonce is threaded end-to-end, at
  which point the nonce alone would suffice and the timestamp adds a
  clock-skew failure mode (the freshness-window pattern the repo
  already states lives in `SecurityMinimumBar.md:134-136`) for no
  added strength. (Review R4: the previously cited
  `CrossNetworkLiveLabPrerequisitesChecklist.md` does not exist and
  has been dropped.)
- More code: schema field + producer change + validated-arg plumbing +
  evaluator logic + schema-version bump decision (v2 vs optional-field
  parse — the optional-field shape weakens the fail-closed property the
  fix is for).
- Rejected for both directions of the comparison: A is strictly stronger
  (no file on the trust path at all) and strictly smaller.

## 4) Offline-testable core for the chosen fix

**Daemon side (`rustynetd`, no signature changes):**
`run_macos_exit_killswitch_precedence_check_command`
(`crates/rustynetd/src/main.rs:2638-2652`) keeps
`write_macos_exit_killswitch_precedence_report`, then prints the
serialized report JSON to **stdout** and the "artifact written to …"
confirmation to **stderr**. Because the write function already owns the
report, serialize from the same value — refactor
`write_macos_exit_killswitch_precedence_report` to return the encoded
`String` (or split a `collect_… -> MacosExitKillswitchPrecedenceReport`
return) so the command never re-serializes divergently. Existing unit
tests on the write function keep passing; one new pin test:
`precedence_check_stdout_is_report_json` (stdout parses as the schema,
stderr carries the confirmation).

**Adapter side (`rustynet-cli`, pure + offline):**

- New pure helper in `macos_exit_traffic.rs`:
  `fn extract_precedence_report_stdout(raw: &str) -> Result<&str, String>`
  — requires the captured stdout to be exactly one JSON document
  (trimmed), rejecting empty output, the confirmation-line-only output,
  leading/trailing non-JSON text, and non-object documents. Fail-closed
  on every non-verbatim shape.
- `run_killswitch_precedence_baseline` (`:638-672`) drops the `cat`
  read-script (`:655-663`) and evaluates
  `extract_precedence_report_stdout(stdout_of_check)?` through the
  unchanged `evaluate_macos_exit_killswitch_precedence_artifact`.

**The evaluator's new rejections (all error, never pass):** under A the
evaluator itself keeps its shape contract; the *rejection surface* moves
to the extraction boundary — stale/foreign bytes cannot reach the
evaluator because no path reads them. Concretely new-rejected inputs:
empty stdout, confirmation-line-only stdout, junk-wrapped JSON, and any
future daemon whose stdout is not the artifact (fail closed instead of
falling back to the file — **no fallback branch is permitted**, per the
one-hardened-path rule, AGENTS.md §3).

**Named unit tests (adapter-side, `#[cfg(test)]`, offline):**

1. `precedence_stdout_capture_accepts_fresh_verbatim_json` — a captured
   stdout that is exactly the serialized report parses and evaluates to
   the pass string (fresh accepted; the only accept test).
2. `precedence_stdout_capture_rejects_empty_stdout` — empty/whitespace
   capture is an error (missing evidence fails closed).
3. `precedence_stdout_capture_rejects_confirmation_line_only` — the
   pre-fix stdout shape ("artifact written to …") is an error, pinning
   that the daemon-side change is load-bearing.
4. `precedence_stdout_capture_rejects_leading_or_trailing_text_around_json`
   — junk-wrapped JSON is an error (no lenient substring extraction).
5. `killswitch_precedence_baseline_sequence_has_no_artifact_path_read` —
   structural pin: the baseline's command list no longer contains a
   `cat` of `MACOS_EXIT_KILLSWITCH_PRECEDENCE_ARTIFACT_PATH`, so a
   future edit cannot silently reintroduce the fixed-path read. (Under
   the rejected Option B the equivalent set would have been: fresh
   accepted; stale/old-`captured_at_unix` rejected; missing-freshness-
   field rejected fail-closed; nonce-mismatch rejected — recorded here
   so the weaker variant's test intent is not lost.)

## 5) Crates changed + collision surface

- **`rustynetd` (`crates/rustynetd`)**: `main.rs:2638-2652` (stdout
  JSON / stderr confirmation) + `macos_exit_killswitch_precedence.rs`
  (return the encoded report from the write path; no schema change).
  *Product crate.* Daemon-verifier surface only; no enforcement path
  touched.
- **`rustynet-cli`** (`crates/rustynet-cli`): `macos_exit_traffic.rs`
  (capture + extract + drop `cat`). *Lab tooling behind the `vm-lab`
  feature (RNQ-17).*
- **Legacy stage call sites — CORRECTED per review R2 (the plan's
  original claim here was wrong).** The fixed path's only consumer was
  the adapter's `cat`. The legacy Stage 9
  (`validate_macos_exit_killswitch_precedence`, `mod.rs:12244-12313`)
  reads a different input: the per-run captured copy under
  `report_dir/macos_exit_evidence` (`mod.rs:11893`, `:12272`, collected
  via `:13050`), gated on mesh-join and capture success — it does not
  carry the fixed-path stale-file defect and was NOT migrated by this
  fix. Dropping the adapter's `cat` therefore closed the stale-file leg
  completely on its own. The legacy stage's absent→Skip posture is
  recorded here as out of F2 scope.
- **In-flight macOS DNS three-state fix note (review §3):**
  `macos_dns_failclosed.rs:60-62` imports
  `MACOS_RUSTYNET_ANCHOR_PREFIX` and `validate_pf_anchor_name` from
  `macos_exit_killswitch_precedence.rs`. This fix renamed neither; keep
  it that way while the DNS fix is in flight. The files are disjoint,
  so the two changes may land in either order.
- **R3 applied (preferred form):** the adapter's check invocation drops
  `--output` entirely, so no file is created at the fixed path on the
  lab path — the stale-artifact side channel is eliminated rather than
  merely unread. The daemon keeps `--output` as an optional
  operator/forensics mode (the legacy per-run capture script still
  passes it, now against its per-run report directory).
- Both crates changed → per the operating contract this needs
  **plan → review → impl** (this document is the plan; an adversarial
  refute pass on it, then the implementation commit) rather than a
  single-drive edit.
- **Collision surface:** the just-landed adapter wiring
  (`3f0be0c1`, reviewed in
  `MacosExitServingAdapterWiringPostMergeReview_2026-09-02.md`) owns the
  same function (`run_killswitch_precedence_baseline`) and the same
  file. Follow-up **F1** of that review (`:206-214`) also edits
  `macos_exit_traffic.rs:23` (deleting/narrowing the module-level
  `allow(dead_code)`) — disjoint lines, but land serially to keep the
  blame clean.

## 6) Live-lab proof stage and unknowns

**Proof stage: the macOS exit cell.** The fixed sequence runs live only
when a macOS node is elected into the Exit role
(`ai_lab_run exit_platform=macos` / `--node macos-utm-1:exit`), inside
the pre-activation baseline of `MacosExitActivationSequence`. Note the
predicate state honestly (review F3,
`MacosExitServingAdapterWiringPostMergeReview_2026-09-02.md:229-236`):
the macOS `active_exit` predicate is currently false by design, and the
live vehicle for the sequence is the
`exit_nat_lifecycle_validation` reactivation
(`stage/exit_nat_lifecycle_validation.rs:97-111`) whenever a macOS node
holds the Exit role — that stage is the evidence stage for this fix, not
a bypass. The cell remains gated behind **CP-1**, triaged 2026-08-29 as
environmental (lab network topology, the macOS↔Debian pairing;
`CrossPlatformRoleParityRefresh_2026-07-23.md:117-134`), so a green
live proof additionally requires the CP-1 networking work or a topology
that avoids the blocked pairing.

**Unknown / needs-live (no evidence invented):**

- Whether the daemon's stdout capture survives the adapter's SSH
  plumbing unchanged (the snapshot path already proves the mechanism for
  one command, but the precedence check is the *mutating* one — its
  stdout must stay clean under `sudo -n` on the guest; `ssh.rs:575-579`
  trims, which is safe for a JSON document but means any guest-side
  MOTD/shell noise would fail the strict extraction — that failing
  loudly is correct, but its likelihood is unmeasured).
- Whether the 120 s `EXIT_COMMAND_TIMEOUT`
  (`macos_exit_traffic.rs:576`) still bounds the experiment once the
  capture path changes (it should — no new work is added — but the
  live stage is the only place that is proven).
- The post-baseline A2 restore snapshot (`:669-671`) must still pass
  with the new sequence in place — unproven until the macOS exit cell
  runs.
- Guest-binary version skew (§1.2(b)) cannot be reproduced offline; the
  structural no-file-read pin (test 5) is the offline proxy, and the
  live run is where the daemon/CLI pairing is actually exercised.

