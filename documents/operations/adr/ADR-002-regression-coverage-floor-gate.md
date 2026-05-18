# ADR-002: Per-module regression-coverage floor gate

- Status: Accepted
- Date: 2026-05-17

## Context

Rustynet relies heavily on `#[test]` blocks to pin security-tied
invariants: DNS fail-closed behaviour, killswitch boot ordering, ACL
shapes, signature/thumbprint policies, mesh-status freshness bounds,
custody invariants, exit-code mappings, and the secret-leak scanners
themselves. The `SecurityPostureSummary.md` Section 1 table shows
each verifier module's pinned test count.

The risk: silent test-suite shrinkage during a refactor. A contributor
splits a module, moves files around, accidentally deletes a whole
`#[test] fn drift_when_dns_mode_changes() { ... }` block, and the
green CI run says nothing — the remaining tests still pass. The
deleted invariant is now unguarded but nobody is told.

Concrete scenarios that motivated this:

- A `mod tests { ... }` block can be lost during a module-tree
  reorganisation when the `mod tests;` line at the parent fails to
  carry forward.
- A `cfg(test)` block can be lost when a `#[cfg(target_os = "linux")]`
  bracket is widened during a cross-platform change.
- A whole `#[test]` function can be deleted alongside the production
  code it covered, when the production code is being rewritten but
  the test should have been re-pointed.

Alternatives considered:

- **Total-test-count floor.** Pin the total `cargo test --workspace`
  passing count at N and fail if it drops. Rejected: catches gross
  shrinkage but misses targeted shrinkage. If `linux_dns_failclosed`
  loses 5 tests while a sibling module gains 5, the total holds and
  the regression ships. Per-module floors catch this; a total floor
  does not.
- **Coverage-percent floor (e.g. `cargo llvm-cov` line-coverage at X%).**
  Rejected as a primary defence: line coverage rewards code-line
  density, not invariant density. A 10-line invariant test and a
  100-line happy-path test contribute equally to invariant safety but
  10× differently to coverage. We want the inverse weighting.
- **Mutation testing (`cargo mutants`).** Considered as a complement,
  not a substitute. Mutation testing answers "do tests catch a
  mutation?"; the floor gate answers "do the tests still exist?".
  Both questions matter; only the second is cheap enough to run on
  every PR.
- **Code-owner review.** Necessary but not sufficient — humans miss
  silently-deleted tests when the diff is large.

## Decision

Land `scripts/ci/regression_coverage_gates.sh`. For each
security-tied module in the gated list, the script runs
`cargo test --lib <module>::` and asserts the passing-test count is
`>=` a pinned floor. The script fails closed (non-zero exit) on any
shortfall, naming the module and the observed-vs-expected counts.

Pinned set at acceptance (2026-05-17):

- 14 modules at floor (7 Linux verifiers + 7 Windows verifiers).
- 407 pinned tests in aggregate across those 14 modules.

Pinned set as of 2026-05-18 (post platform-improvement-backlog
X4/X7 expansions; tracked here so the ADR snapshot doesn't drift
from the live gate while the script is the source of truth):

- 22 modules at floor across 4 groups: linux (7) + macos (6) +
  windows (8) + shared (1).
- 615 pinned tests in aggregate (linux 196 + macos 74 +
  windows 278 + shared 67).
- The `shared` group covers platform-agnostic audit modules
  (currently `secret_log_audit`); it was added when the X3 static
  scanner's self-tests warranted the same silent-removal
  protection the per-platform verifier modules already had.
- Full per-module list in `SecurityPostureSummary.md` Section 1
  and in `scripts/ci/regression_coverage_gates.sh`.

The gate is part of every release-readiness check and runs alongside
`cargo fmt`, `cargo clippy`, `cargo test`, `cargo audit`, and
`cargo deny check` per the project's CLAUDE.md Section 7 contract.

Floor bumps are intentional: when a module gains a legitimate new
test, the floor is bumped in the same commit, and the commit message
records what invariant the new test pins.

## Consequences

**Positive**

- Silent test-suite shrinkage trips a named failure that points at
  the exact module and the exact shortfall — no archaeology required.
- The floor value is itself a reviewable artifact in the script.
  Reviewers see "floor went 33 → 34 in this PR" and can correlate
  with the new test in the diff.
- Cheap to run (one `cargo test --lib <module>::` per gated module).
- Composes with mutation testing if and when we add it: the floor
  guarantees the test bodies are still present; mutation testing
  asserts they still bite.

**Negative**

- Each module floor bump requires a deliberate edit to
  `regression_coverage_gates.sh` and a commit message that explains
  the new invariant. This is friction by design, but it is friction.
- A module rename requires a coordinated edit to the gate script
  and the production code. Mitigated by the script's per-module
  failure message pointing operators directly at the script.
- Does not catch the case where a test is rewritten to assert
  something weaker. Only mutation testing or review catches that.
  We accept this gap; the gate is one layer of defence.
- The gate is `>=`, not `==`. A new test added in the same PR
  without a floor bump still passes the gate. This is deliberate:
  the gate's job is to catch shrinkage, not to mandate floor edits
  on every test addition. The next floor bump in any subsequent PR
  picks up the new test naturally.

## Implementation

Primary script: `scripts/ci/regression_coverage_gates.sh`.

Composition:

- Hard-coded per-module floor table (module path → expected passing
  test count).
- One `cargo test --lib <module>:: --no-fail-fast` invocation per
  gated module.
- Output parser that extracts the passing count and compares to
  the floor.
- Fail-closed exit with a named, actionable error message on shortfall.

The gated set at acceptance (14 modules, 407 tests) matched the
verifier modules listed in `SecurityPostureSummary.md` Section 1.
Adding a new verifier module to the gate is a deliberate two-line
edit (the table row + the floor). The current gated set has grown
to 21 modules across 4 groups as the X4 coverage-parity sweep
expanded the matrix; see the snapshot under "Decision" above for
the live count.

## Related

- [`../SecurityPostureSummary.md`](../SecurityPostureSummary.md) — Section 1 holds the live floor table.
- [ADR-001](./ADR-001-secret-log-audit.md) — the secret-leak audit relies on this gate to pin its own scanner-self-test count so the scanners cannot be silently deleted.
- Backlog items X4 and X7 (Platform Improvement Backlog 2026-05-14).
- CLAUDE.md Section 7 (Validation and CI Gates) — establishes the broader gate-discipline contract this gate participates in.
