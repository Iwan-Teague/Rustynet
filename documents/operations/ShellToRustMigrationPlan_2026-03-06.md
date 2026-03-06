# Shell-to-Rust Security Migration Plan

Date: 2026-03-06  
Owner: Rustynet engineering

## 1) Goal
Migrate the most security-critical shell logic (`.sh`) into Rust while preserving current Linux/macOS behavior and keeping Debian 13 compatibility as a hard constraint.

Success criteria:
- reduced privileged shell attack surface,
- no regression in fail-closed behavior,
- no regression in key custody controls,
- all current gates and VM validation scenarios still pass.

## Status Update (2026-03-06)
- Phase A complete: `refresh_trust_evidence.sh` and `refresh_assignment_bundle.sh` are thin wrappers to Rust ops commands.
- Phase B complete: `install_rustynetd_service.sh` is now a thin wrapper to `rustynet ops install-systemd`; core installer logic (idempotent user/group/dir setup, credential-path pinning, env file generation, legacy cleanup/migration, systemd orchestration) is implemented in Rust.

## 2) Current Risk Inventory (Impact-First)
High-impact scripts by privilege + secret handling + size:

1. `start.sh` (~4435 lines)
- Handles key/passphrase custody flows, role switching, trust/assignment generation paths, and privileged orchestration.
- Highest long-term security/maintenance risk due to breadth and complexity.

2. `scripts/systemd/refresh_trust_evidence.sh` (root, timer-driven)
- Uses signer key + passphrase source, writes trust artifacts, validates ownership/mode.
- High impact because it runs unattended as root.

3. `scripts/systemd/refresh_assignment_bundle.sh` (root, timer-driven)
- Uses assignment signing secret + passphrase source, signs bundle, writes verifier/bundle artifacts.
- High impact because it runs unattended as root and controls tunnel policy inputs.

4. `scripts/systemd/install_rustynetd_service.sh` (root installer)
- Creates users/groups/directories, writes service units/env, checks custody paths.
- High impact due to system-wide mutation and policy wiring.

Lower priority (keep shell for now):
- `scripts/ci/*.sh`, `scripts/e2e/*.sh`, release/evidence generation scripts.
- These are mostly orchestration/test glue and should remain thin shell wrappers.

## 3) Migration Strategy
Use a staged approach with compatibility wrappers, not a big-bang rewrite.

Principles:
- move privileged + secret-sensitive operations first,
- keep shell only as thin dispatch/wrapper where OS integration is unavoidable,
- preserve current command interfaces until replacements are proven,
- fail closed on all parse/path/permission errors.

## 4) Target Architecture
## 4.1 Rust command surface
Extend `rustynet` CLI with privileged ops commands:
- `rustynet ops refresh-trust`
- `rustynet ops refresh-assignment`
- `rustynet ops install-systemd` (Linux)
- follow-up: additional setup/role-switch subcommands currently embedded in `start.sh`.

## 4.2 Shell role after migration
- `start.sh`: interactive UX wrapper only.
- systemd helper scripts: temporary wrappers calling Rust commands, then removed after stabilization.
- CI/e2e shell scripts remain orchestration wrappers.

## 4.3 Shared secure utilities (Rust)
Centralize in reusable module(s):
- strict path validation (absolute path, no symlink, expected owner/group/mode),
- atomic write + fsync + chmod/chown,
- scrub+remove helper for sensitive files,
- typed env parsing with strict bounds and explicit defaults,
- secret handling via `Zeroizing` where material may enter memory.

## 5) Phased Plan
## Phase A (highest security ROI): systemd refreshers
Scope:
- Replace logic of:
  - `scripts/systemd/refresh_trust_evidence.sh`
  - `scripts/systemd/refresh_assignment_bundle.sh`
- Keep scripts as wrappers initially:
  - `exec /usr/local/bin/rustynet ops refresh-trust`
  - `exec /usr/local/bin/rustynet ops refresh-assignment`

Security requirements:
- Preserve/strengthen checks already present:
  - root-only execution,
  - absolute paths,
  - symlink rejection,
  - root ownership for signing key/passphrase sources,
  - allowed mode policy including `/run/credentials/*` semantics,
  - atomic output writes and strict output modes.
- No secrets in stdout/stderr; keep log lines metadata-only.

Validation:
- new unit tests for env parsing and permission matrices,
- negative tests: weak perms, symlink paths, missing passphrase, invalid TTL,
- run:
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  - `cargo test --workspace --all-targets --all-features`
  - `./scripts/ci/phase10_gates.sh`
  - `./scripts/ci/membership_gates.sh`

Exit criteria:
- systemd timers operate through Rust path with parity behavior,
- wrappers remain for quick rollback.

## Phase B: service installer migration
Scope:
- Port `scripts/systemd/install_rustynetd_service.sh` core logic into:
  - `rustynet ops install-systemd`
- Keep shell installer as compatibility wrapper during transition.

Security requirements:
- strict ownership/mode setting with explicit expected values,
- idempotent directory/user/group creation,
- explicit credential blob path pinning enforcement,
- safe env file generation (no shell injection footguns).

Validation:
- idempotency tests (run twice = no drift),
- unit file integrity checks,
- Debian 13/Mint/Ubuntu/Fedora install-reinstall checks.

Exit criteria:
- fresh install works on supported Linux distros without manual network cleanup.

## Phase C: `start.sh` risk decomposition
Scope:
- Migrate sensitive operational subflows first:
  - signing passphrase materialization/decryption,
  - trust/assignment signing helper actions,
  - role-switch state mutation and assignment refresh coupling,
  - secure cleanup operations.
- Keep menu rendering/prompt UX in shell initially.

Security requirements:
- reduce shell branching around secret-bearing paths,
- move path/env validation to typed Rust structs,
- eliminate direct shell parsing of signed artifact fields where possible.

Validation:
- menu-driven regression checks (admin/client/blind_exit),
- one-hop/two-hop selection and reconnect tests,
- live exit handoff under load test.

Exit criteria:
- `start.sh` becomes a thin UI wrapper over Rust ops commands.

## Phase D: optional full Rust operator UX
Scope:
- optional terminal UX port from shell menu to Rust (later), if desired.
- not required for security hardening completion.

## 6) Cross-Platform Safety Guardrails
Linux (Debian 13, Mint, Ubuntu, Fedora):
- primary migration target for root/systemd scripts.

macOS:
- do not regress launchd flow or keychain custody.
- keep existing macOS shell orchestration until Linux migrations are stable.

Guardrail:
- no migration step may weaken current fail-closed defaults or secret custody policy.

## 7) Rollout + Rollback
Rollout model:
1. Introduce Rust command.
2. Swap shell script body to `exec rustynet ops ...` wrapper.
3. Run gates + VM matrix.
4. Keep old shell implementation in history for one release cycle.

Rollback model:
- Repoint wrappers/services back to previous shell implementation by reverting one commit or switching ExecStart target.
- No state schema changes in Phase A/B to keep rollback low-risk.

## 8) Test Matrix Per Phase
Mandatory per-phase checks:
1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings`
3. `cargo check --workspace --all-targets --all-features`
4. `cargo test --workspace --all-targets --all-features`
5. `./scripts/ci/phase10_gates.sh`
6. `./scripts/ci/membership_gates.sh`

VM runtime validation:
1. Debian 13 client <-> exit
2. Mint client -> Debian exit
3. Ubuntu client/exit role swap
4. Fedora client/exit role swap
5. macOS compatibility sanity (no Linux migration side effects)

Network behavior checks:
- one-hop and two-hop path correctness,
- exit reselection/disconnect semantics,
- no leak during exit handoff under load,
- NAT egress through selected exit verified.

## 9) Recommended First Implementation Slice (start now)
Implement Phase A first in this order:
1. Add `rustynet ops refresh-trust` (parity with `refresh_trust_evidence.sh`).
2. Add `rustynet ops refresh-assignment` (parity with `refresh_assignment_bundle.sh`).
3. Convert both shell scripts into thin wrappers.
4. Re-run gates + Debian/Mint validation.

Reason:
- highest security impact,
- smallest migration surface compared with `start.sh`,
- easiest to validate with existing timers/gates.
