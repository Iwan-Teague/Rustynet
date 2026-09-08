# Review — LocalUtmProbeFlakeReview_2026-09-08

Adversarial review of branch `ai-edit/edit-1788826975456-81448-0`, commit `7255df3a`
("De-flake local_utm_process_present_uses_wide_ps_output by injecting an unreachable probe
budget"), against `main`. The change de-flakes
`vm_lab::tests::local_utm_process_present_uses_wide_ps_output`
(`crates/rustynet-cli/src/vm_lab/mod.rs:44628`), which failed once under heavy host load
(QH-77, `QualityHardeningTodo_2026-07-25.md`).

Scope note first, because it changes what "the diff" means. `git diff main..HEAD` shows
79 deletions across two files, but the commit itself is +17/−7 on two files. The ~72-line
discrepancy is staleness, not content: the branch's merge-base with `main` is `9bace4e1`
and `main` has since gained `1b587028` (the QH-78 decision) and `b0eaf343` (the QH-79
closure), so the diff view shows those main-side entries as "deleted". The commit contains
neither deletion. Everything below was verified against the commit's actual content
(`git show 7255df3a --stat`), not the staleness-inflated diff.

## Answers to the review questions

### (1) Fixed at cause, or papered over?

Fixed at cause. The only change to the test is the probe budget argument,
`Duration::from_secs(30)` → `Duration::MAX` (mod.rs:44664-44666). This is not a widened
timeout and not a loosened assertion:

- The deadline was the flake's cause, and it is removed rather than relaxed. In
  `run_output_with_timeout_preserve` the timeout branch is
  `if started_at.elapsed() >= timeout` (mod.rs:35178); `elapsed()` is a real monotonic
  duration, so it can never reach `Duration::MAX` (≈ 5.8×10^11 years) and the branch is
  unreachable. The test's outcome now depends only on the stub's behaviour.
- `Duration::MAX` survives the probe's floor: `local_process_probe_timeout`
  (mod.rs:87-89) is `operator_timeout.max(Duration::from_secs(20))` — a floor, not a cap —
  so `MAX.max(20 s)` is still `MAX`. (Worth stating because a cap-based helper would have
  silently re-introduced a deadline; this one does not.)
- No assertion changed. The `assert!(present)` and the `axww -o command` args-log
  assertion (mod.rs:44668-44674) are byte-identical to the pre-change test; the stub
  script (mod.rs:44636-44644) is unchanged.

The ledger's claim that this is "deliberately not a 30→60 s widening" is accurate.

### (2) Does the test still fail if wide-ps-output parsing regresses?

Yes, on the real spawn+parse path, via three concrete mutations:

- Narrow the production argument list: change
  `command.args(["axww", "-o", "command"])` (mod.rs:35508) to a plain `ps`. The stub
  echoes its arguments into `ps-args.log`, and the assertion at mod.rs:44669-44674
  compares the log to the exact string `"axww -o command"` — the test fails. This is the
  mutation the test was written to catch (`ps ax` truncates output and would miss long
  QEMU command lines on a real host).
- Break the needle match: change `"QEMULauncher"` to `"QEMUHelper"` in
  `local_utm_process_present_in_ps_output` (mod.rs:35524-35529). The stub's output line
  (mod.rs:44639) contains `QEMULauncher` plus the bundle path, so the match goes false,
  `present` comes back `false`, and `assert!(present)` (mod.rs:44668) fails.
- Break the parse entirely (always-`false` parser, or the from_utf8 → parse chain at
  mod.rs:35516-35518 short-circuits): same failure at mod.rs:44668.

The path exercised is genuinely the production one:
`local_utm_process_present_with_ps` → `Command::new(ps_path)` spawn →
`run_output_with_timeout` → exit-status check → `String::from_utf8` → parser
(mod.rs:35502-35522). Nothing is mocked behind the budget argument.

One overclaim in the new comment (mod.rs:44661-44662): it says "a broken needle match or
UTF-8 handling trips the `present` assertion". The UTF-8 clause is not testable by this
test — the stub emits valid UTF-8 (`printf '%s\n'`), so removing or corrupting the
`String::from_utf8` error path (mod.rs:35516-35517) cannot fail this test; only a full
parse break can. Finding N1 below.

### (3) Was production code changed to suit the test?

No. The commit touches only the test body (the budget argument plus an explanatory
comment) and the QH-77 ledger disposition. `local_utm_process_present_with_ps`,
`run_output_with_timeout[_preserve]`, and `local_utm_process_present_in_ps_output` are
byte-unchanged. Production callers (`local_utm_process_present_with_probes` at
mod.rs:35457-35478, called from mod.rs:7040, 30519, 35243, 35436) keep their real,
operator-supplied budgets with the 20 s floor — the infinite budget exists only inside
this unit test, where there is nothing genuine to bound. Correct as-is; nothing to
evaluate on production merits because nothing in production moved.

### (4) Was the test weakened, split, or narrowed?

No. Same single test, same stub, same spawn path, same two assertions, same cleanup. The
only semantic loss is theoretical and pre-existing: the test never exercised the timeout
branch before either (the stub exits in milliseconds against a 30 s budget), so removing
the deadline deletes no coverage.

### (5) Other tests with the same wall-clock sensitivity — does the fix generalise?

It does not generalise, and the ledger says so honestly. Three sibling tests pass the same
`Duration::from_secs(30)` budget through the same probe path via
`transition_local_utm_vm_with_process_probe` (mod.rs:35234-35249 →
`local_utm_process_present_with_probes`):

- `transition_local_utm_vm_skips_stop_when_vm_is_already_stopped` — budget at
  mod.rs:44727,
- `transition_local_utm_vm_skips_stop_when_utmctl_probe_spawn_fails_but_ps_reports_stopped`
  — mod.rs:44773 (two stub spawns, double the exposure),
- `transition_local_utm_vm_accepts_timeout_when_vm_reaches_stopped_state` — mod.rs:44835.

Mitigations the siblings have that the flaked test lacks: all three call
`prime_executable_if_macos` on their stubs (mod.rs:44718, 44764, 44826; the helper,
mod.rs:38875-38885, pays the Gatekeeper first-exec validation cost on a throwaway
invocation) — which is consistent with the one unprimed test,
`local_utm_process_present_uses_wide_ps_output`, being the one that flaked. The third
sibling is deliberately a timeout-semantics test (its utmctl stub sleeps and the test
asserts the wait-with-timeout reconciliation), so injecting `Duration::MAX` there would
change what it tests; the ledger correctly says to confirm semantics before touching it.
The two skip-stop siblings could take the same `Duration::MAX` treatment as a follow-up;
that is a recorded deferral (QH-77 disposition names all three with line refs), not a
hidden gap. Minor: the ledger's line refs (44730/44776/44838) are ~3 lines past the
actual budget lines (44727/44773/44835) — same call sites, drifted citations.

## Findings

### N1 — nit — `crates/rustynet-cli/src/vm_lab/mod.rs:44661-44662`
Defect: the new comment claims "broken ... UTF-8 handling trips the `present`
assertion", but the stub emits valid UTF-8, so a regression confined to the
`String::from_utf8` error path (mod.rs:35516-35517) cannot fail this test.
Failure scenario: a future change replaces the strict UTF-8 check with `from_utf8_lossy`
or drops the error branch; the comment leads the next reader to believe this test guards
it, and it does not.
Suggested fix: drop "or UTF-8 handling" from the comment, or add a stub that emits invalid
UTF-8 and asserts the probe errors — either resolves the mismatch.

### N2 — nit — `crates/rustynet-cli/src/vm_lab/mod.rs:44664-44666`
Defect: `Duration::MAX` converts any pathological stall (a stub that never exits, a host
in total scheduling meltdown) from a 30 s false failure into an unbounded test hang, and
cargo-nextest has no per-test timeout (AGENTS.md §7) — a hung test holds the whole pool.
Failure scenario: a wedged CI runner shows no failure and no diagnosis, only an outer
timeout; strictly worse triage than the flake it replaces, if the stub could ever hang
(here it is `#!/bin/sh` plus two `printf`s, so realistically it cannot).
Suggested fix: none required; acceptable for a deterministic `/bin/sh` stub. If the team
wants belt-and-braces, a very large finite budget (e.g. 1 h) keeps the same
load-immunity with a hard backstop. Documented trade-off, deliberately taken — recording
it here so it is on the record.

### P1 — procedural — branch staleness (merge mechanics, not a defect in the commit)
Defect: none in the commit. The branch is 2 commits behind `main`
(`git rev-list --count HEAD..main` = 2), so the `git diff main..HEAD` view carries ~72
lines of phantom deletions (the QH-79 entry and the QH-78 decision that landed on `main`
after the merge-base `9bace4e1`).
Failure scenario: applying the branch as a patch-style diff instead of a git merge would
revert two landed ledger entries. A git merge will not (the branch changed only the QH-77
disposition line plus the test; `main`'s two commits touch the adjacent QH-79/QH-78
sections, so a merge is expected to apply cleanly with possible adjacent-hunk fuzz).
Suggested fix: merge via a git merge of the branch (or rebase onto `main` first); never
apply this branch as a raw patch.

## Verified non-findings

- Ledger provenance: the QH-77 disposition names worktree branch
  `ai-edit/edit-1788823521793-19065-0`, not this branch's id. Both refs resolve to the
  same commit `7255df3a`, so the citation is accurate.
- Q1-Q4 answered above: no assertion loosened, no production change, no test split, real
  spawn path retained; the fix is at cause, verified by tracing the actual code
  (`local_process_probe_timeout` floor at mod.rs:87-89; unreachable timeout branch at
  mod.rs:35178), not from function names.
- Verification run on this branch: `cargo fmt --all -- --check` exit 0;
  `cargo test -p rustynet-cli --lib --all-features --locked
  local_utm_process_present_uses_wide_ps_output` — 1 passed in 0.65 s (no wall-clock
  dependence observable).

Nothing blocking was found. The change does exactly what its commit message and ledger
disposition claim, the flake class is fixed at cause for the affected test, and the
deferral of the three sibling tests is documented in the owning ledger rather than
silently dropped. N1 and N2 are comment-accuracy and trade-off-recording nits that can be
addressed in a follow-up or at merge time at the reviewer's discretion.

VERDICT: MERGE — the fix removes the load-sensitive deadline without touching assertions
or production code and retains behavioural regression coverage on the real spawn+parse
path; the only findings are two comment/record-accuracy nits and a merge-mechanics
caution (merge the branch, never patch it).
