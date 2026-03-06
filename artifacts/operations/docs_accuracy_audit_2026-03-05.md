# Docs Accuracy Audit (2026-03-05)

## Scope
- Reviewed: `README.md`, `documents/Requirements.md`, `documents/SecurityMinimumBar.md`, `documents/phase10.md`, and selected operations/status docs that make concrete implementation claims.
- Compared documentation claims against current code in `crates/` and `scripts/`.

## Executive Summary
- Overall: **mostly accurate for current runtime behavior**, with **notable drift in some historical/security assessment docs**.
- Key issue types:
  - historical findings left in place without a superseded status marker,
  - enforcement docs overstating leakage-gate coverage,
  - stale line-anchored references in one remediation plan,
  - legacy key-custody/path assumptions in operations docs.

## Confirmed Accurate
- macOS dependency hardening in README matches runtime/setup behavior:
  - README says non-admin fallback is blocked and root-owned tool paths are required.
  - Enforced in code: non-admin path fails closed ([start.sh:1076](../../start.sh#L1076), [start.sh:1077](../../start.sh#L1077), [start.sh:1080](../../start.sh#L1080)).
  - Root-owned binary enforcement exists ([start.sh:1881](../../start.sh#L1881), [start.sh:1882](../../start.sh#L1882)).
- Transport abstraction exists and is used in core dataplane/controller flows:
  - Contract trait ([crates/rustynet-backend-api/src/lib.rs:140](../../crates/rustynet-backend-api/src/lib.rs#L140)).
  - Generic controller usage ([crates/rustynetd/src/phase10.rs:1556](../../crates/rustynetd/src/phase10.rs#L1556)).
- Trust auto-refresh setup behavior in README aligns with install logic:
  - Timer enable/disable path exists ([scripts/systemd/install_rustynetd_service.sh:386](../../scripts/systemd/install_rustynetd_service.sh#L386), [scripts/systemd/install_rustynetd_service.sh:391](../../scripts/systemd/install_rustynetd_service.sh#L391), [scripts/systemd/install_rustynetd_service.sh:393](../../scripts/systemd/install_rustynetd_service.sh#L393)).

## Drift / Inaccuracy Findings
1. **Historical gap doc is stale if read as current state (`SimulationSecurityGapAssessment.md`)**
- Doc claim: runtime accepts `in-memory` backend in production ([documents/SimulationSecurityGapAssessment.md:104](../../documents/SimulationSecurityGapAssessment.md#L104), [documents/SimulationSecurityGapAssessment.md:106](../../documents/SimulationSecurityGapAssessment.md#L106)).
- Current code:
  - CLI only accepts `linux-wireguard` / `macos-wireguard` ([crates/rustynetd/src/main.rs:399](../../crates/rustynetd/src/main.rs#L399), [crates/rustynetd/src/main.rs:401](../../crates/rustynetd/src/main.rs#L401)).
  - `InMemory` mode is rejected in non-test builds ([crates/rustynetd/src/daemon.rs:526](../../crates/rustynetd/src/daemon.rs#L526), [crates/rustynetd/src/daemon.rs:529](../../crates/rustynetd/src/daemon.rs#L529)).
- Assessment: **outdated historical finding**, should be explicitly marked superseded/remediated.

2. **Leakage-gate documentation overstates coverage**
- Docs state leakage outside adapter crates blocks release ([documents/operations/BackendAgilityValidation.md:12](../../documents/operations/BackendAgilityValidation.md#L12)).
- Gate implementation is case-sensitive ([scripts/ci/phase10_gates.sh:102](../../scripts/ci/phase10_gates.sh#L102)).
- Lowercase `wireguard` references exist in a scanned crate ([crates/rustynet-control/src/ga.rs:250](../../crates/rustynet-control/src/ga.rs#L250), [crates/rustynet-control/src/ga.rs:256](../../crates/rustynet-control/src/ga.rs#L256)).
- Assessment: enforcement exists, but documentation claim is stronger than current regex coverage.

3. **Cross-platform remediation plan contains stale line-anchored evidence**
- GAP-02 references non-admin fallback evidence at old line anchors ([documents/operations/CrossPlatformSecurityGapRemediationPlan_2026-03-05.md:73](../../documents/operations/CrossPlatformSecurityGapRemediationPlan_2026-03-05.md#L73)).
- Current code now enforces fail-closed admin requirement and root-owned binaries (see `start.sh` refs above), and README is updated accordingly ([README.md:32](../../README.md#L32)).
- Assessment: as a dated plan this is useful context, but several anchors now point to shifted code and should be refreshed or marked historical snapshots.

## Notes on Document Types
- `documents/Requirements.md` is explicitly a roadmap/requirements artifact (“Brainstorm v0.3”, [documents/Requirements.md:1](../../documents/Requirements.md#L1)); it should be treated as normative target-state, not current implementation status.

## Applied Updates (Round 2)
1. Added superseded/historical status context to `documents/SimulationSecurityGapAssessment.md` and marked F5 as remediated in current code.
2. Updated `documents/operations/BackendAgilityValidation.md` to avoid overclaiming leakage enforcement and explicitly document case-sensitivity risk.
3. Updated `documents/operations/CrossPlatformSecurityGapRemediationPlan_2026-03-05.md` with verified current status, remediation state markers, and security-risk truths for regression-critical controls.
4. Added `documents/operations/PlatformSupportMatrix.md` as a current-state platform/security source of truth.
5. Linked current-state matrix from:
   - `README.md`
   - `documents/phase10.md` (status note clarifying Linux phase scope vs current cross-platform implementation)

## Applied Updates (Round 3)
1. Added explicit backend-agility policy/code discrepancy notes:
   - current in-tree `TunnelBackend` implementations are WireGuard + stub,
   - second non-simulated backend implementation remains pending code work.
2. Added direct/relay failover scope correction:
   - phase/progress docs now note current Phase10 behavior is path-mode signaling/audit, with full relay transport integration still pending.
3. Corrected outdated custom-signing finding:
   - `SimulationSecurityGapAssessment.md` F4 now marks old SHA256 payload-signing claim as mostly superseded and points to current Ed25519 sign/verify paths, with residual key-derivation review note.

## Applied Updates (Round 4)
1. Updated `documents/operations/Phase10ExitNodeDataplaneRunbook.md`:
   - corrected stale legacy `/etc/rustynet/wireguard.*` precondition paths to current hardened Linux paths,
   - replaced plaintext passphrase-file assumption with encrypted credential blob requirement,
   - added explicit security-risk truth and failover-artifact limitation note.
2. Updated `documents/operations/RustynetdServiceHardening.md`:
   - corrected required runtime key-custody files to credential-only passphrase handling,
   - explicitly marked persistent plaintext passphrase file as disallowed in hardened runtime,
   - added security-risk truth for stale plaintext-key assumptions.
3. Updated `documents/Phase10CompletionReport.md`:
   - added status-correction banner for historical overclaims,
   - replaced non-deferred statement with explicit open deferment for full relay transport failover integration.
4. Updated `documents/ExecutionProgress.md`:
   - added status-correction banner,
   - corrected Phase 9 completion/task checklist for open non-simulated-backend gap,
   - corrected final completion ledger to avoid overclaiming full closeout.
5. Updated `documents/Phase10ExecutionProgress.md`:
   - corrected final ledger items that still reported full completion despite open relay-transport failover scope gap.
6. Updated `documents/FinalImplementationReport.md`:
   - corrected final completion wording to avoid overclaiming full closure while backend-agility and relay-failover code gaps remain open.

## Remaining Work (Security-Relevant)
1. Leakage gate hardening is still needed in CI scripts:
   - Current regex remains case-sensitive; this is a medium boundary-erosion risk.
2. macOS dataplane CI depth is still lower than Linux real E2E depth:
   - Current macOS coverage is smoke + targeted tests; deeper integration/leak testing remains recommended.
3. Linux-only guards still restrict some manual peer admin flows on macOS:
   - Operational parity work remains open.
4. Backend agility policy/code discrepancy remains:
   - Docs/policy require an additional non-simulated backend path, but current in-tree `TunnelBackend` implementations are WireGuard + stub.
   - This is now explicitly documented in backend-agility and launch-checklist docs as needing code work.
5. Direct/relay failover claim depth discrepancy:
   - Phase docs/progress previously read as full relay transport failover under real dataplane conditions.
   - Current Phase10 runtime implementation primarily records path-mode transitions (`Direct`/`Relay`) and audit signals; full relay dataplane transport switching remains a code gap.
