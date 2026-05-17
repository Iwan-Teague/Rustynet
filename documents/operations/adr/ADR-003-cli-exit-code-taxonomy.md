# ADR-003: Shared CLI exit-code taxonomy

- Status: Accepted
- Date: 2026-05-17

## Context

Rustynet ships ~71 CLI binaries under `crates/rustynet-cli/src/bin/`
(verifiers, drift checkers, lab orchestrators, ops emitters, gate
scripts, etc.). Before this decision, every `bin/*.rs` was using
bare `std::process::exit(1)` (or simply returning `Err(...)` from
`main`, which collapses to exit-code 1) for every non-zero outcome.

This had three concrete operator-impact problems:

1. **Shell wrappers couldn't tell failure shapes apart.** A
   `phase10_gates.sh` loop that ran a verifier and a config-validator
   in sequence had no way to distinguish "config is malformed
   (exit 65)" from "transient IO blip, retry safe (exit 70)" from
   "fail-closed policy verdict, retrying will retry the same verdict
   (exit 78)" — every failure was exit 1.
2. **`systemd RestartPreventExitStatus=` was useless.** systemd's
   restart-prevention list takes exit-code integers; with everything
   exiting 1, you either restart on every failure (including
   PolicyReject) or restart on none. Both are wrong.
3. **Retry loops silently retried fail-closed verdicts.** CI loops
   that wrapped a verifier with "retry up to 3 times on transient
   failure" would happily retry a real `PolicyReject` three times,
   burning lab time and (worse) producing three identical fail-closed
   reports in the evidence bundle — making it look like a transient
   problem instead of a real one.

Alternatives considered:

- **Per-binary custom codes.** Each binary picks its own integer
  meanings. Rejected: cross-binary consumers (the shell wrappers,
  the systemd unit, the CI orchestrator, the artifact-collector) need
  a stable mapping. Per-binary schemes mean every consumer needs a
  per-binary translation table, and adding a binary means updating
  every consumer.
- **Bash-style binary codes (success vs anything).** Status quo.
  Rejected for the reasons above.
- **Adopt `sysexits.h` literally as named codes.** Rejected as
  insufficient — `sysexits.h` is C-header territory and doesn't
  carry into Rust call sites cleanly. We want a Rust enum so the
  type system surfaces the choice at every exit point.
- **`anyhow::Result`-with-typed-error-tag.** Considered, but the
  exit-code mapping still needs a single point of truth at the
  process boundary. The enum is that point of truth; how individual
  binaries propagate their failure internally is left to them.

## Decision

Land a six-variant `ExitCode` enum at
`crates/rustynetd/src/exit_codes.rs`:

| Code | Variant            | Meaning                                                  |
|------|--------------------|----------------------------------------------------------|
| 0    | `Success`          | command did what was asked                               |
| 1    | `GenericFailure`   | last-resort fallback                                     |
| 64   | `BadArgs`          | invalid argv / missing required flag / unknown sub       |
| 65   | `ConfigError`      | on-disk config failed validation                         |
| 70   | `TransientFailure` | IO / network / retry-safe                                |
| 78   | `PolicyReject`     | fail-closed gate refused the operation                   |

The integer values are aligned with BSD `sysexits.h`:
`EX_USAGE=64`, `EX_DATAERR=65`, `EX_SOFTWARE=70`, `EX_CONFIG=78`.
This lets existing tooling — shell wrappers that already understand
`sysexits.h`, `systemd RestartPreventExitStatus=` lists, CI retry
loops written against BSD conventions — work against Rustynet
without any Rustynet-specific knowledge.

The retry contract for shell wrappers and CI loops:

> Retry only on exit-code 70 (`TransientFailure`). Treat 64, 65, 78
> as terminal. Treat 1 as terminal-but-investigate (we shouldn't be
> producing 1 from any reviewed binary — it's the last-resort
> fallback).

Every `bin/*.rs` binary classifies its failure shapes through the
enum. Security-critical verdicts (signature verification,
attestation, drift detection, tampering detection, leak detection,
performance regression, platform mismatch) uniformly map to
`PolicyReject(78)` so retry-only-on-70 loops cannot accidentally
retry a fail-closed verdict.

## Consequences

**Positive**

- Shell wrappers, `systemd RestartPreventExitStatus=64 65 78`, and
  CI retry loops work correctly without per-binary glue.
- The enum at the process boundary is a typed compile-time
  reviewable artifact — `grep -r 'ExitCode::PolicyReject'` enumerates
  every fail-closed exit point in the workspace.
- `sysexits.h` alignment means external operators familiar with BSD
  conventions read Rustynet exit codes correctly on first contact.
- Retry loops no longer burn lab time retrying real fail-closed
  verdicts.
- Evidence bundles no longer accumulate spurious "three identical
  failures, must be transient" patterns from retried `PolicyReject`s.

**Negative**

- All ~71 `bin/*.rs` binaries had to be migrated. Done in 7
  parallel-agent batches; one-time cost.
- Adding a new binary requires the author to think about its failure
  taxonomy. Intentional friction.
- The enum lives in the `rustynetd` crate; binaries in
  `rustynet-cli` take a dependency on it. Acceptable — the enum is
  small, has no runtime dependencies, and the dependency is in the
  right direction (CLI depends on core, not the reverse).
- Code `1` (`GenericFailure`) is a deliberate escape hatch and a
  failure mode — any new exit-code-1 site is a code-review red flag
  to be classified properly.

## Implementation

Primary module: `crates/rustynetd/src/exit_codes.rs` — the `ExitCode`
enum, its `as_i32()` / `From<ExitCode> for i32` mappings, and the
helper(s) that wrap `std::process::exit`.

Coverage: 100% of `bin/*.rs` binaries under
`crates/rustynet-cli/src/bin/` (~71 binaries) classify their failure
shapes through the taxonomy. Security-critical verdicts uniformly map
to `PolicyReject(78)`.

Operator runbook:
[`../CliExitCodeTaxonomy.md`](../CliExitCodeTaxonomy.md) — documents
the retry contract, the systemd-unit integration pattern, and the
decision tree operators use when triaging a non-zero exit.

Migration ran in 7 parallel-agent batches across the ~71 binaries.

## Related

- [`../CliExitCodeTaxonomy.md`](../CliExitCodeTaxonomy.md) — operator runbook for the taxonomy established here.
- [`../SecurityPostureSummary.md`](../SecurityPostureSummary.md) — Section 2 records the live coverage and the `PolicyReject` mapping rule.
- Backlog item X6 (Platform Improvement Backlog 2026-05-14).
- BSD `sysexits.h` — original source of the 64/65/70/78 integer choices.
