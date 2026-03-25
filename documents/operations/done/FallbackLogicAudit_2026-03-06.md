# Fallback / Legacy Path Audit (Security Focus)

Date: 2026-03-06

## Scope
Code-path audit for fallback, downgrade, compatibility, and legacy behavior in runtime and setup logic.

## Implementation Status (2026-03-06 Pass 3)
- Implemented in prior pass:
  - `FL-001`, `FL-002`, `FL-003`, `FL-004`, `FL-005`
  - `FL-017`, `FL-018`, `FL-020`, `FL-021`, `FL-025`, `FL-028`
- Implemented in pass 2:
  - `FL-007`, `FL-009`
  - `FL-012`, `FL-013`, `FL-014`, `FL-015`, `FL-016`
  - `FL-019`
  - `FL-022`, `FL-023`, `FL-024`, `FL-026`, `FL-027`
- Implemented in pass 3:
  - `FL-006`, `FL-008`, `FL-010`, `FL-011`
- Implemented in pass 4:
  - `FL-013`
- Remaining for next passes:
  - none

## Priority 1: Runtime Downgrade Paths (Most Important)

### FL-001: Rust ops failure downgrades to shell implementation
Where:
- `start.sh:578-640` (`ensure_signing_passphrase_material`)
- `start.sh:663-735` (`materialize_signing_passphrase_file`)
- `start.sh:1735-1815` (`prepare_system_directories`)
- `start.sh:2060-2142` (`ensure_membership_files`)
- `start.sh:2152-2182` (`lockdown_blind_exit_local_material`)
- `start.sh:2207-2270` (`refresh_signed_trust_evidence`)
- `start.sh:2458-2475` (`write_daemon_environment` installer path)
- `start.sh:3216-3255` (`set_local_assignment_refresh_exit_node`)
- `start.sh:3371-3415` (`switch_node_role` coupling path)

Why it exists:
- Transition period while migrating shell flows to Rust.

What can go wrong:
- Rust and shell code paths can diverge in validation, permissions, or failure behavior.
- Attack surface stays larger because shell path remains live.

How to make one secure route:
1. Replace each warning fallback branch with hard failure (`return 1` / `exit 1`) when Rust op fails.
2. Keep shell code physically present only behind explicit `RUSTYNET_ENABLE_LEGACY_FALLBACK=1` compile-time/profile gating during transition.
3. Remove legacy shell branches completely after one release cycle.

### FL-002: Secure-delete fallback is best-effort and error-suppressing
Where:
- `start.sh:555-575` (`secure_remove_file_with_scope`)

Why it exists:
- Compatibility when `rustynet ops secure-remove` is unavailable.

What can go wrong:
- Fallback path suppresses wipe errors (`|| true`), making cleanup failures silent.
- Security guarantees differ by platform/tool availability.

How to make one secure route:
1. Require `rustynet ops secure-remove` success; if it fails, fail closed.
2. Remove `shred`/truncate shell fallback from production path.
3. Keep shell cleanup only in dedicated recovery/debug scripts, not normal runtime.

### FL-003: Role/lockdown actions intentionally ignore errors
Where:
- `start.sh:2882` (`lockdown_blind_exit_local_material || true`)
- `start.sh:3927` (same during first-run)
- `start.sh:3392-3406` (role switch post-actions with `|| true`)

Why it exists:
- UX continuity during partial failures.

What can go wrong:
- Security-critical transitions may partially apply and continue.
- Can leave stale privileged/signing material present.

How to make one secure route:
1. Treat these as transactional operations: any failure aborts role switch/start.
2. Add explicit rollback if mutation step fails.
3. Emit a hard error state requiring operator acknowledgment before retry.

### FL-004: Assignment env mutation falls back to inline shell text rewrite
Where:
- `start.sh:3216-3255`

Why it exists:
- Backward compatibility if `rustynet ops set-assignment-refresh-exit-node` fails.

What can go wrong:
- Shell rewrite path is harder to validate and reason about than typed Rust config mutation.

How to make one secure route:
1. Remove `bash -lc` fallback branch.
2. Require Rust command success.
3. Add unit/integration tests around Rust env-file mutation edge cases (duplicate keys, empty values, malformed lines).

### FL-005: WireGuard custody still has compatibility fallback for unsupported binary
Where:
- `start.sh:1924-1935`

Why it exists:
- Older installed `rustynet` binaries may not have `ops bootstrap-wireguard-custody`.

What can go wrong:
- Behavior can vary by binary version on the same host class.

How to make one secure route:
1. Enforce minimum `rustynet` CLI version before setup starts.
2. Remove unsupported-command compatibility fallback.
3. Fail with explicit upgrade instruction instead of running legacy shell path.

## Priority 2: Crypto / Key-Custody Fallbacks

### FL-006: OS secure store fallback to encrypted local file
Where:
- `crates/rustynet-crypto/src/lib.rs:350-378`

Why it exists:
- Cross-platform operation when OS secure store is unavailable.

What can go wrong:
- Local encrypted-file backend is weaker than OS/hardware-backed boundary.
- Inconsistent security posture across platforms/hosts.

How to make one secure route:
1. Introduce strict mode: `require_os_secure_store=true` (no local fallback).
2. Make strict mode default for production profiles.
3. Keep fallback only in explicitly non-production profiles.

### FL-007: Local signing fallback is allowed by default in policy type
Where:
- `crates/rustynet-crypto/src/lib.rs:505-515`

Why it exists:
- Default flexibility for testing/bring-up.

What can go wrong:
- Future callers using `Default` can implicitly permit weaker provider fallback.

How to make one secure route:
1. Change default to `allow_local_fallback: false`.
2. Require explicit opt-in where local fallback is truly needed.
3. Add compile-time profile checks to ban local fallback in release builds.

### FL-008: Explicit emergency macOS passphrase-file fallback toggle
Where:
- Env knob: `crates/rustynetd/src/key_material.rs:33`
- Gate logic: `crates/rustynetd/src/key_material.rs:178-187`, `337-341`
- launchd currently sets disabled: `start.sh:2818-2819`

Why it exists:
- Emergency recovery escape hatch.

What can go wrong:
- Runtime env override can re-enable file passphrase path.

How to make one secure route:
1. Remove runtime env toggle in production build/profile.
2. Keep recovery behavior in a separate offline recovery binary/tool.
3. Add startup gate that hard-fails if this env var is set in production mode.

### FL-009: "fallback" crypto helper APIs remain first-class
Where:
- `crates/rustynet-crypto/src/lib.rs:687-738` (`encrypt_private_key_fallback`, `decrypt_private_key_fallback`)

Why it exists:
- Shared implementation naming from earlier custody design.

What can go wrong:
- Naming and API surface encourage ongoing fallback semantics.

How to make one secure route:
1. Rename to neutral mandatory API (`encrypt_private_key_envelope`), or move behind internal module.
2. Disallow direct external use from runtime code paths unless policy permits.
3. Add lint/test gates forbidding fallback API use in production crates.

## Priority 3: Legacy Data Compatibility Paths

### FL-010: Legacy watermark formats still accepted
Where:
- Trust watermark parser accepts v1 without payload digest:
  - `crates/rustynetd/src/daemon.rs:3040-3103`
- Auto-tunnel watermark parser accepts v1 without payload digest:
  - `crates/rustynetd/src/daemon.rs:3595-3660`

Why it exists:
- Backward compatibility with older persisted watermark files.

What can go wrong:
- Mixed trust-state semantics across nodes and upgrade states.
- Increased parser complexity for trust-sensitive state.

How to make one secure route:
1. Add explicit migration step to rewrite v1 files to v2 before daemon start.
2. After migration window, reject v1 outright.
3. Add CI gate that fails if repository/runtime fixtures still emit v1.

### FL-011: Legacy key path migration still active in installer and custody bootstrap
Where:
- `crates/rustynet-cli/src/main.rs:1489-1490`, `1663-1693`, `1715-1724`
- `crates/rustynet-cli/src/ops_install_systemd.rs:408-492`, `1371-1393`
- `start.sh:1842`, `1895-1896`, `1913-1914`, `1998-2004`, `2043`

Why it exists:
- Upgrade support from old key/passphrase locations.

What can go wrong:
- Transitional legacy paths remain part of active code and testing burden.

How to make one secure route:
1. Move legacy migration to explicit one-time migration command.
2. Remove implicit migration from normal startup paths.
3. Enforce canonical path set only after migration completion marker.

## Priority 4: Operational Compatibility Fallbacks (Lower Security Impact)

### FL-012: Systemd wrappers resolve binary via PATH if canonical path missing
Where:
- `scripts/systemd/refresh_trust_evidence.sh:4-7`
- `scripts/systemd/refresh_assignment_bundle.sh:4-7`
- `scripts/systemd/install_rustynetd_service.sh:5-8`

Why it exists:
- Convenience for non-standard installs.

What can go wrong:
- PATH-dependent resolution is less deterministic.

How to make one secure route:
1. Require absolute pinned binary path only.
2. Fail if missing.
3. Verify file owner/mode/hash before exec.

### FL-013: Default egress interface fallback (`eth0`/`en0`)
Where:
- historical `start.sh` default-interface guessing path
- historical daemon/sample-unit default `RUSTYNET_EGRESS_INTERFACE=eth0`

Why it exists:
- Setup convenience when autodetection fails.

What can go wrong:
- Wrong interface guess can cause routing misconfiguration.

Current status:
- implemented
- `start.sh` now fails when it cannot derive a real egress interface instead of guessing,
- `rustynetd` default `egress_interface` is now `auto` rather than `eth0`,
- sample systemd wiring now uses `RUSTYNET_EGRESS_INTERFACE=auto` and daemon startup resolves the actual default-route interface before dataplane preflight.

### FL-014: Hostname fallback in systemd installer
Where:
- `crates/rustynet-cli/src/ops_install_systemd.rs:1606-1617`

Why it exists:
- Ensure a node hostname value is always available.

What can go wrong:
- Lower observability quality, not primary cryptographic risk.

How to make one secure route:
1. Require explicit hostname env/config input for installer.
2. Fail if missing/invalid.

### FL-015: Dependency installer fallback for ripgrep via cargo
Where:
- `start.sh:1383-1397`

Why it exists:
- macOS usability when Homebrew is absent.

What can go wrong:
- Non-uniform toolchain/provenance across systems.

How to make one secure route:
1. Require one package manager path per platform.
2. Fail with installation instructions rather than alternate installer logic.

## Priority 1 (Addendum): Additional Runtime Downgrade Paths

### FL-016: macOS runtime path coercion still relies on compatibility namespace defaults
Where:
- `start.sh:117-137` (`apply_host_profile_defaults`)
- `start.sh:153-166` (`coerce_macos_path_var`)
- `start.sh:219-237` (`enforce_host_storage_policy`)

Why it exists:
- Keep older path conventions and mixed host-profile configs working during migration.

What can go wrong:
- Silent path rewrites hide config drift instead of forcing explicit correction.
- `compat/...` namespace keeps legacy assumptions alive for trust/assignment/key paths.

How to make one secure route:
1. Define one canonical macOS path set without `compat/` aliases.
2. Move coercion to a one-time migration command that writes canonical values.
3. Fail startup when non-canonical storage paths are detected after migration.

### FL-017: Pre-start trust refresh failure is warn-only when auto-refresh is enabled
Where:
- `start.sh:2885-2887`

Why it exists:
- Preserve startup continuity during transient signer/refresh failures.

What can go wrong:
- Service can start with stale trust evidence even when refresh is explicitly enabled.
- Startup security behavior differs between “refresh succeeded” and “refresh failed but continued” states.

How to make one secure route:
1. If `AUTO_REFRESH_TRUST=1` and signer material is present, require successful refresh before daemon start.
2. On refresh failure, abort startup with explicit remediation guidance.
3. Keep a separate explicit break-glass command for emergency manual starts (audited, time-bounded).

### FL-018: Temporary signing-passphrase file ownership/mode hardening suppresses errors
Where:
- `start.sh:675-677`
- `start.sh:692-693`
- `start.sh:713-714`

Why it exists:
- Tolerate chown/chmod quirks across privilege boundaries in mixed setups.

What can go wrong:
- Temporary passphrase files may remain with incorrect owner/mode without failing the operation.
- Security guarantees depend on ambient filesystem defaults instead of enforced custody.

How to make one secure route:
1. Treat `chown`/`chmod` failures as hard errors.
2. Secure-remove temp files immediately on permission-hardening failure.
3. Prefer Rust-side materialization that atomically creates the temp file with final owner/mode.

### FL-019: VPN disconnect teardown is mostly best-effort and can leave residual dataplane state
Where:
- `start.sh:2923-2935` (macOS helper/PF cleanup ignores failures)
- `start.sh:2954-2993` (Linux route/rule/nft/sysctl cleanup is warn-only)

Why it exists:
- Prioritize user recoverability even when some teardown steps fail.

What can go wrong:
- Residual routing/firewall state can persist across reconnects and role changes.
- Hard-to-diagnose stale network state increases operational and security risk.

How to make one secure route:
1. Replace shell teardown with one Rust “disconnect/cleanup” op that returns structured residual-state errors.
2. Fail disconnect when critical cleanup steps do not complete.
3. Offer a separate explicit `ops recover-network` command for forced remediation paths.

## Priority 2 (Addendum): Additional Crypto / Key-Custody Fallbacks

### FL-020: Systemd installer has a separate weaker secure-remove implementation
Where:
- `crates/rustynet-cli/src/ops_install_systemd.rs:1411-1447`

Why it exists:
- Historical local utility implementation inside installer module.

What can go wrong:
- Behavior diverges from stricter secure-remove logic used elsewhere.
- Non-regular file targets return success (`Ok(())`) without explicit operator visibility.

How to make one secure route:
1. Consolidate all secure-delete calls onto one shared Rust implementation.
2. Return explicit errors for unsupported file types (except not-found).
3. Require fsync + truncation/wipe semantics consistency across all call sites.

### FL-021: Daemon key-material deletion uses best-effort scrub with suppressed write errors
Where:
- `crates/rustynetd/src/key_material.rs:516-548`

Why it exists:
- Avoid blocking deletion when overwrite/sync operations are partially unavailable.

What can go wrong:
- Scrub write/sync failures are not surfaced, so wipe guarantees are unverifiable.
- Sensitive file deletion can silently degrade to plain remove behavior.

How to make one secure route:
1. Convert best-effort scrub to strict scrub that returns errors.
2. Propagate failures to callers for revoke/cleanup operations.
3. Add tests that assert failure on scrub I/O errors rather than silent continuation.

### FL-022: Denylisted algorithm handling includes compatibility-exception bypass path
Where:
- `crates/rustynet-crypto/src/lib.rs:149-167`
- `crates/rustynet-crypto/src/lib.rs:179-189`

Why it exists:
- Controlled temporary compatibility path for denylisted algorithms.

What can go wrong:
- A denylisted algorithm can be accepted through exception wiring, which preserves a downgrade route.
- Exception model is expiry-based at this layer and does not itself enforce richer signed risk context.

How to make one secure route:
1. Remove runtime algorithm exceptions in production profile.
2. If exceptions must exist, require signed risk-acceptance payloads and enforce them at the validation boundary.
3. Add gate checks that fail production builds when exception list is non-empty.

## Priority 4 (Addendum): Additional Operational Compatibility Fallbacks

### FL-023: CI security-gate toolchain resolution falls back to ambient cargo toolchain
Where:
- `scripts/ci/phase1_gates.sh:81-87`, `94-97`
- `scripts/ci/phase10_gates.sh:81-87`, `94-97`
- `scripts/ci/membership_gates.sh:81-87`, `94-97`

Why it exists:
- Keep gates runnable when pinned security toolchain is unavailable.

What can go wrong:
- Security scan behavior varies by environment/toolchain availability.
- Gate outcomes become less deterministic across hosts.

How to make one secure route:
1. Require one pinned security toolchain and fail if unavailable.
2. Require one deterministic advisory-db source path (pre-synced artifact).
3. Remove fallback branch that runs `cargo` without the pinned toolchain.

### FL-024: Dependency/bootstrap flows still include compatibility install branches with dynamic remote installers
Where:
- `start.sh:1083` (Homebrew installer via remote script)
- `start.sh:1187-1199` (cargo-deny compatibility version branch)
- `start.sh:1208` (rustup bootstrap via remote script)

Why it exists:
- Simplify first-run bootstrap across diverse host states.

What can go wrong:
- Multiple bootstrap paths increase provenance and reproducibility variance.
- Security posture depends on live network installer behavior.

How to make one secure route:
1. Use a single package/bootstrap route per platform with pinned versions/checksums.
2. Fail setup when required toolchain packages are not present from approved source.
3. Keep remote-script bootstrap as documented manual break-glass only.

Update 2026-03-07:
- Operator/bootstrap flow in `start.sh` now uses host package-manager `rustup` plus the pinned workspace toolchain from `rust-toolchain.toml`; ambient distro `cargo`/`rustc` fallback is removed from that path.
- Remote E2E host bootstrap (`rustynet ops e2e-bootstrap-host`) now enforces the pinned repo toolchain when it performs its own build and skips the redundant privileged rebuild path when the caller already installed the binaries.
- Assignment refresh env writers now emit quoted env-file assignments for structured values (`RUSTYNET_ASSIGNMENT_NODES`, `RUSTYNET_ASSIGNMENT_ALLOW`, and related fields), closing the raw-shell metacharacter parsing path in both systemd `EnvironmentFile` consumption and shell-sourced E2E harnesses.
- Signing passphrase materialization now decrypts into a fresh secure temp directory path and atomically publishes the requested output; the ad hoc direct decrypt-to-existing-file pattern is removed from the live E2E matrix path.
- CI helper script `scripts/ci/bootstrap_ci_tools.sh` still needs separate remediation before FL-024 can be considered fully closed repository-wide.

### FL-025: macOS launchd bootout helper suppresses unload errors
Where:
- `start.sh:2631-2643`
- Called by: `start.sh:2849-2850`, `2871-2872`

Why it exists:
- Tolerate differences in launchd bootout syntax and unit state.

What can go wrong:
- Stale launchd units can persist without visibility when both bootout forms fail.
- Subsequent bootstrap may run against partially stale service state.

How to make one secure route:
1. Keep dual-syntax attempt if needed, but require one explicit success condition.
2. If both attempts fail, fail the operation with actionable diagnostics.
3. Add explicit post-check (`launchctl print`) to verify unit unload state.

### FL-026: Invalid persisted config values are silently coerced to defaults
Where:
- `start.sh:277-284` (invalid/unsupported `NODE_ROLE` -> `client`)
- `start.sh:788-821` (invalid `EXIT_CHAIN_HOPS`/launch defaults reverted)

Why it exists:
- Keep startup/menu flow resilient when config contents are malformed.

What can go wrong:
- Misconfiguration or tampering can be masked by silent coercion.
- Operators may not realize runtime posture changed from intended configuration.

How to make one secure route:
1. Treat invalid persisted security-relevant config as startup error, not auto-rewrite.
2. Provide explicit `ops repair-config` command that validates and rewrites values with operator confirmation.
3. Persist only validated config schema versions and reject unknown/invalid fields.

### FL-027: Network/backend parameters are coerced to safe defaults instead of requiring explicit correction
Where:
- `start.sh:240-243` (invalid macOS `WG_INTERFACE` -> `utun9`)
- `start.sh:448-457` (unsupported backend forced to host expected backend)
- `start.sh:479-483` (invalid WireGuard listen port -> `51820`)

Why it exists:
- Improve setup survivability across partial or stale configurations.

What can go wrong:
- Runtime may proceed with unintended interface/backend/port values.
- Silent coercion can hide deployment drift and complicate incident response.

How to make one secure route:
1. Fail on invalid backend/interface/port with explicit remediation output.
2. Keep defaults only for initial provisioning, never for previously persisted configs.
3. Add startup integrity check that blocks run when persisted values are out of policy.

### FL-028: Trust/assignment publication group selection falls back to root group when daemon group is missing
Where:
- `crates/rustynet-cli/src/main.rs:3295-3301` (`group_gid_or_root`)
- `crates/rustynet-cli/src/main.rs:1227-1233` (trust refresh publication mode selection)
- `crates/rustynet-cli/src/main.rs:1353-1368` (assignment refresh directory ownership)

Why it exists:
- Keep refresh operations running on hosts where daemon group bootstrap is incomplete.

What can go wrong:
- Group-custody intent is silently downgraded to root-group ownership.
- Permission profile changes depend on host bootstrap state instead of explicit policy.

How to make one secure route:
1. Remove root-group fallback and require daemon group existence before refresh/install operations.
2. Fail with explicit remediation (`ops install-systemd` / group bootstrap) when missing.
3. Add test coverage asserting no implicit group fallback for trust/assignment artifact ownership.

## Execution Order To Remove Fallbacks Safely

1. Remove Priority 1 items (`FL-001` through `FL-005`) and enforce fail-closed runtime behavior.
2. Apply strict custody/provider policy (`FL-006` through `FL-009`) with production profile gates.
3. Migrate and drop legacy format/path acceptance (`FL-010`, `FL-011`).
4. Remove addendum runtime/custody downgrade paths (`FL-016` through `FL-022`).
5. Harden operational determinism and CI/bootstrap consistency (`FL-012` through `FL-015`, `FL-023` through `FL-028`).
