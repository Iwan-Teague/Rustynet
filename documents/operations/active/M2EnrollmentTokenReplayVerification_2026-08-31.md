# M-2 Verification — Enrollment Token Replay / Concurrency

Date: 2026-08-31
Subject: finding M-2 from `LiveLabCoverageGapAudit_2026-08-31.md` (L25, L51, L91; control
text cited from `SecurityMinimumBar.md` §3.3, L210–214)
Method: read-only code tracing + quote-aware parsing of the run-matrix ledger against the
working tree; no code was changed.

## Verdict

**REFUTED — high confidence**, with two narrow residues stated below so nothing is
over-claimed.

The audit's M-2 says enrollment one-time-credential race/replay is "untested live" and
labels it **NEW**, claiming `live_enrollment_restart_validation` is "the only live stage".
Both halves are wrong against the real tree:

1. The control is **enforced in production code**: a single-use on-disk consumed-token
   ledger, an OS advisory file lock (flock) serializing the entire
   load → check-consumed → register → write read-modify-write (RSA-0023's prescribed
   fix), and HMAC/expiry/skew rejection before any ledger mutation.
2. The control is **proven live**: three dedicated live-lab stages
   (`validate_linux_enrollment_replay`, `validate_macos_enrollment_replay`,
   `validate_windows_enrollment_replay`) each drive an adversarial in-process battery —
   `rustynetd enrollment-replay-audit` — ON the guest, asserting sequential replay is
   denied (`AlreadyConsumed`), 8 concurrent racers yield exactly ONE redemption, and a
   distinct-token baseline proves the guard is not vacuously denying everything. The
   `--node` evidence ledger records **83 pass** rows for `linux_enrollment_replay` and
   **11 pass** rows for `macos_enrollment_replay`.

What does remain (and it is not what M-2 claims):

- The Windows cell exists in the registry but has **never run** (242/242 `not_run` in the
  ledger) — the standing per-cell parity posture owned by
  `CrossPlatformRoleParityRefresh_2026-07-23.md`, not a new M-2-specific gap.
- The live battery proves the race at the locked ledger read-modify-write sequence (the
  exact primitives `handle_enrollment_consume` uses), not by counting mesh members after a
  full multi-request redemptions storm; and the battery's three cases do not include a
  wrong-skew replay case (enforcement + unit tests for skew/expiry exist; the live battery
  just does not re-assert them).
- Lockout/backoff on the consume path genuinely does not exist — but that is a **separate
  already-tracked finding** (ENR-10, open, in
  `AdversarialSecurityRemediation_2026-07-29.md` L441), and SecurityMinimumBar §3.3 lists
  rate limiting and lockout/backoff as their own bullets (L211–212), distinct from the
  atomic-consumption bullet M-2 quotes (L214).

**Release-blocking: NO** (as M-2 frames it at audit L91). The core single-use/atomicity
control is enforced and live-proven on Linux and macOS.

**Already tracked: YES** — RSA-0023 (`SecurityAuditLedger_2026-06-18.md`, fix applied in
code), ENR-1/TOCTOU-1 (the adversarial audit's own case ids),
`LiveLabSecurityTestCoverage_2026-06-22.md` already maps ENR-1 to
`validate_linux_enrollment_replay` (L48, L639), and ENR-10/ENR-14 in
`AdversarialSecurityRemediation_2026-07-29.md` own the lockout and stale-ledger-row
residues. M-2's "NEW" label is wrong on both the enforcement and the test axis.

## The claim, restated

> [HIGH, NEW — M-2] Enrollment one-time-credential race/replay is untested live. §3.3
> (L210–214) demands atomic, race-safe single consumption under concurrent requests; the
> only live stage (`live_enrollment_restart_validation`) tests a daemon restart
> mid-enrollment, not concurrency or post-redemption replay. (audit L25)

Table row M-2 (audit L51) proposes closing stage
`enrollment_replay_concurrency_validation`: N parallel redemptions of one token → exactly
one member; replayed token → rejected; wrong-skew replay → rejected; lockout/backoff
observable. M-2 is listed P0/release-blocking (audit L91).

## Evidence

### 1. Enforcement — the consume path is locked, single-use, and fail-closed

`crates/rustynetd/src/daemon.rs`, `handle_enrollment_consume` (signature L9590), reached
from the local IPC socket AND the anchor enrollment stream (L9580–9583):

- **Capability gate first** (L9597–9613): `require_local_signed_capability` for
  `RoleCapability::AnchorEnrollmentEndpoint` runs before the secret is read, before the
  ledger lock, and before any attacker-supplied byte is parsed.
- **Parse-before-lock abuse bound** (L9626–9649): pubkey base64/32-byte and Ed25519
  verification-key checks, push-address parse — all before contending on the ledger lock
  (a flood of malformed consumes cannot hold the single-use ledger's exclusive lock).
- **RSA-0023 fix — exclusive advisory lock over the whole sequence** (L9652–9658):
  `acquire_ledger_lock` (flock, `crates/rustynetd/src/enrollment_token.rs` L791 unix /
  L831 windows) is held across ledger load (L9659–9660) → consume → ledger write, so "two
  concurrent redemptions of the same single-use token cannot both observe 'not
  consumed'" (the code's own comment). The CLI-side operator path uses the identical
  locked sequence (`crates/rustynet-cli/src/main.rs` `consume_enrollment_token_locked`,
  L8263–8280).
- **Single-use check precedes mutation** (`crates/rustynetd/src/enrollment_token.rs`,
  `verify_and_consume_token_with_now`, L1000): constant-time HMAC tag compare FIRST so a
  tampered token never reaches the ledger (L1010–1018, `TagMismatch`), issued-in-future
  skew rejection (L1019–1023, `IssuedInFuture` beyond
  `ISSUED_AT_FUTURE_TOLERANCE_SECS`), expiry rejection (L1024–1028, `Expired`), and only
  then `ledger.was_consumed` → `AlreadyConsumed` (L1029–1031) **before** the mutation
  (`record_consumed` L1032). No TOCTOU window inside the function, and the flock removes
  the one between processes/threads.
- **Persistence before registration, fail-closed**
  (`crates/rustynetd/src/enrollment_consume.rs` L209–217, module doc L10–24): the ledger
  write happens BEFORE peer registration; a spool write failure aborts the consume, so a
  crash cannot leave "registered without a durable ledger entry" (which would allow one
  re-redemption). `write_ledger` (L654) persists atomically; the ledger is on disk, so
  the single-use semantic survives a daemon restart. Expired entries are pruned
  conservatively on every redemption (`purge_expired_against`, L396) with a write-side
  full-ledger check kept as defense-in-depth (L457–458).

Unit tests assert exactly the properties M-2 demands, in the production modules:
`replay_after_consume_returns_already_consumed` (`enrollment_consume.rs` L321), a
rejected token must NOT be recorded as consumed (L312–314), and
`enrollment_consume_refused_when_capability_absent` /
`enrollment_consume_capability_gate_precedes_subsystem_and_token_checks`
(`daemon.rs` L22276, L22291).

### 2. The adversarial live battery — ENR-1 + TOCTOU-1 against the real code path

`crates/rustynetd/src/enrollment_replay_audit.rs` (wired as the
`rustynetd enrollment-replay-audit` subcommand, `crates/rustynetd/src/main.rs` L344,
arg validation L2405, JSON report L2414) drives the REAL shipped enrollment-token
primitives — the same locked
`acquire_ledger_lock → load_ledger → verify_and_consume_token_with_now → write_ledger`
sequence `handle_enrollment_consume` runs (module doc L1–32) — against a throwaway
on-disk ledger:

- **ENR-1, sequential replay** (L84–149): redeem the same token twice; first MUST
  succeed, second MUST fail with exactly `AlreadyConsumed` (L127–133); a second `Ok` is a
  recorded VIOLATION (L141–147).
- **TOCTOU-1, concurrent race** (L151–232): 8 OS threads (`TOCTOU_RACER_COUNT`, L49) race
  the SAME token through the real locked read-modify-write; the case passes only if
  exactly ONE racer redeemed AND the final on-disk ledger holds exactly one entry
  (L206–231) — a double-spend fails loud with a VIOLATION record.
- **Anti-vacuous baseline** (L237–300): two distinct never-seen tokens must BOTH redeem,
  so the guard cannot pass by denying everything.

The unit test `audit_passes_against_the_real_enrollment_token_code_path` (L335) plus
per-case tests (L345–369) gate the battery in CI.

### 3. The live stages — three per-OS cells, fail-loud evaluator

`crates/rustynet-cli/src/live_lab_stage_registry.rs`:

- `validate_macos_enrollment_replay` (L1288–1296, `EnableRule::WantsMacos`, budget 180s),
- `validate_windows_enrollment_replay` (L1616–1624, `EnableRule::WantsWindows`, 180s),
- `validate_linux_enrollment_replay` (L1883–1891, `EnableRule::LinuxLiveSuite`, 300s),

all three carrying `proves: PROVES_ENROLLMENT_REPLAY`, which is exactly
`["ENR-1", "TOCTOU-1", "RSA-0023"]` (L511) — the audit's own proposed proof targets.

Each stage runs `rustynetd enrollment-replay-audit` ON the guest over SSH and evaluates
the JSON with a strict fail-loud validator,
`crates/rustynet-cli/src/vm_lab/mod.rs`:

- runners: linux L23915–23930, macos L23488–23503, windows L23760–23774;
- `evaluate_enrollment_replay_report` (L20863–20898) rejects, with named reasons: wrong
  schema version; a thin battery ("ran only N case(s); expected the full
  sequential-replay + toctou-race + baseline battery"); a regressed denial ("denied only
  N of 2 required cases … ENR-1/TOCTOU-1/RSA-0023 regression suspected"); and a vacuous
  deny-all ("denied the distinct-tokens baseline case; the guard is vacuous");
- dispatch wiring: linux L24163 + L24391–24402 (skipped only when the earlier
  `validate_linux_runtime_acls` stage failed — conditional dispatch, not absence), macos
  L12827–12835, windows L18215–18223; evaluator round-trip + negative tests at
  L46640–46699.

The audit's proposed stage also asks for "replayed token → rejected" (covered, ENR-1) and
"exactly one member" — the battery asserts exactly one successful redemption and exactly
one ledger entry at the consume sequence level (L206–231), which is the atomicity
control §3.3 names; it does not re-count gossip members after the storm. That is the one
honest narrowing of the live proof.

### 4. Ledger evidence — the stages have actually run and passed

Quote-aware parse of `documents/operations/live_lab_node_run_matrix.csv` (the `--node`
engine's ledger, 242 data rows at this commit):

- `linux_enrollment_replay`: **83 pass**, 159 not_run;
- `macos_enrollment_replay`: **11 pass**, 231 not_run;
- `windows_enrollment_replay`: 242 not_run — never run (see Verdict);
- for contrast, `live_enrollment_restart_validation` / `live_enrollment_restart` (the
  stage M-2 wrongly calls the only one; registry L2004–2011, L2064–2065) prove the
  restart/durability property, with `linux_stage_enrollment_restart` at 12 pass / 3 fail.

So "untested live" is false on Linux and macOS: the concurrency and replay properties are
asserted by a fail-loud adversarial battery that has passed 94 times in recorded runs.

### 5. Lineage — this was found, fixed, and wired before the audit

- `SecurityAuditLedger_2026-06-18.md` RSA-0023 (L78, L148, heading L1115): "Enrollment
  one-time-token ledger has no file lock; concurrent (cross-process) consume can redeem
  the same single-use token twice" — prescription: "OS advisory file lock (flock) around
  ledger read-modify-write (mirror resilience.rs acquire_lock); concurrent-consume test"
  (L254). The fix and the test both exist (§1, §2 above).
- The per-file ledger rows for `enrollment_consume.rs` / `enrollment_token.rs` still read
  `open` (L253–254) — stale rows; `AdversarialSecurityRemediation_2026-07-29.md` ENR-14
  (L445) already flags exactly this: "Two per-file ledger rows read `open` for an applied
  RSA-0023 — Update both rows".
- `LiveLabSecurityTestCoverage_2026-06-22.md` already maps the control to the live stage:
  ENR-1 → `validate_linux_enrollment_replay` (L48, L639). An older row (L569) names a
  `validate_linux_enrollment_replay_persistence` id that does not match the registry's
  stage name — the durability property lives in `live_enrollment_restart_validation`
  instead; treat L569 as a stale proposal, not a missing stage.
- Lockout/backoff on the consume path is absent and owned: ENR-10 ("No rate limit or
  attempt counter on the consume path") is open at
  `AdversarialSecurityRemediation_2026-07-29.md` L441. SecurityMinimumBar §3.3 itself
  separates the bullets: rate limiting (L211) and lockout/backoff (L212) are distinct
  controls from the one M-2 quotes, "One-time credential consumption is atomic and
  race-safe under concurrent requests" (L214), and §5's evidence list already demands
  "Concurrent one-time-key consume race tests" (L288) — which §2/§3 above show exist.

## Residuals worth recording (none restate M-2)

1. **Windows cell never run.** The stage exists and is registry-wired but is 242/242
   `not_run`. This is the same per-cell shape as every other Windows column in the
   ledger and is the ParityRefresh program's standing work item — not a new gap, and not
   specific to enrollment.
2. **Wrong-skew replay is not a live-battery case.** Enforcement exists
   (`IssuedInFuture`/`Expired` rejection, `enrollment_token.rs` L1019–1028) and the
   HMAC-before-everything ordering is unit-tested, but the three-case battery does not
   re-assert skew live. Cheap to extend `enrollment_replay_audit.rs` with a fourth case
   if the release wants it; the control itself is enforced.
3. **Battery scope is the consume sequence, not a full member-count storm.** The
   atomicity property is proven where it is implemented (the locked ledger
   read-modify-write) with 8 real racing threads; the audit's "exactly one member"
   phrasing over-specifies what the current stage asserts.

## Bottom line

M-2's control is enforced (locked, single-use, persisted, fail-closed) and adversarially
proven live on Linux (83 pass) and macOS (11 pass) by a stage family the audit did not
know existed, already tracked under RSA-0023 / ENR-1 / TOCTOU-1 with the lockout residue
separately owned by ENR-10. **Not release-blocking as an M-2-shaped gap; the audit's P0
listing (L91) should drop M-2.** The only forward actions are the cheap ones already
tracked: run the Windows cell (ParityRefresh), optionally add a wrong-skew battery case,
and update the two stale `open` RSA-0023 ledger rows (ENR-14).
