# Rustynet Security Review - 2026-03-03

## Scope
- Repository: `Rustynet`
- Commit baseline reviewed: `5a611e1`
- Focus areas: secret/key lifecycle, fail-closed dataplane behavior, privileged IPC handling, startup/preflight trust handling, and Debian runtime behavior.

## Findings And Remediations

### 1) Runtime private key could persist on startup/preflight failure
- Severity: High
- Location: `crates/rustynetd/src/daemon.rs`
- Issue: `run_daemon` decrypted/wrote runtime WG key before preflight, but did not scrub it when preflight/runtime initialization errored.
- Risk: Decrypted key material could remain in `/run/rustynet/wireguard.key` longer than intended.
- Fix implemented:
  - Added guaranteed cleanup path when `run_preflight_checks` fails.
  - Added guaranteed cleanup path when `DaemonRuntime::new` fails.

### 2) Decrypted key buffer not zeroized on write failure
- Severity: High
- Location: `crates/rustynetd/src/daemon.rs`
- Issue: In `prepare_runtime_wireguard_key`, if runtime key write failed, decrypted key buffer could return early before explicit zeroization.
- Risk: Sensitive key material remained in process memory longer than needed.
- Fix implemented:
  - Refactored flow to always zeroize decrypted buffer before error return.
  - Added best-effort removal of partially written runtime key path on write failure.

### 3) Private key buffers in key setup/migration not always cleared on error
- Severity: High
- Location: `crates/rustynetd/src/key_material.rs`
- Issue: `initialize_encrypted_key_material` and `migrate_existing_private_key_material` only zeroized private key on success paths.
- Risk: Key bytes could survive in process memory after mid-function errors.
- Fix implemented:
  - Wrapped operations so private key buffer is zeroized regardless of success/failure.
  - Added best-effort cleanup of partially written output key files on failure.

### 4) Temporary key files could remain on disk after write/sync/rename error
- Severity: High
- Location: `crates/rustynetd/src/key_material.rs`
- Issue: `write_atomic` did not consistently remove temp files on all failure branches.
- Risk: Stranded temp files may retain sensitive key material.
- Fix implemented:
  - Added best-effort temp-file removal on write failure, sync failure, and rename failure.

### 5) IPC command read path was unbounded
- Severity: Medium
- Location: `crates/rustynetd/src/daemon.rs`
- Issue: `read_command` used unbounded `read_line`, allowing large local payloads.
- Risk: Local memory pressure / DoS against daemon socket.
- Fix implemented:
  - Added hard command-size cap (4096 bytes).
  - Added null-byte rejection.
  - Added UTF-8 validation before parse.

### 6) Fail-closed drop rule could be re-added repeatedly
- Severity: Medium
- Location: `crates/rustynetd/src/phase10.rs`
- Issue: `block_all_egress` appended drop rules repeatedly in the same chain.
- Risk: nft chain growth over time, increased complexity/perf degradation.
- Fix implemented:
  - Added idempotence check for a tagged fail-closed drop rule.
  - Added comment marker `rustynet_fail_closed_drop` and skip duplicate insertion.

### 7) Linux secure-store decode path could retain sensitive key material on parse error
- Severity: High
- Location: `crates/rustynet-crypto/src/lib.rs`
- Issue: `load_from_linux_secret_service` only zeroized the retrieved key string after successful hex decode.
- Risk: Encoded private key material could remain in process memory if decode failed.
- Fix implemented:
  - Refactored decode flow to always zeroize the retrieved string before returning (success or failure).

### 8) Derived encryption key not always zeroized on crypto failure
- Severity: High
- Location: `crates/rustynet-crypto/src/lib.rs`
- Issue: Fallback `encrypt_private_key_fallback` / `decrypt_private_key_fallback` returned early on AEAD errors before wiping the derived key buffer.
- Risk: Derived key bytes could remain in memory on exceptional paths.
- Fix implemented:
  - Added explicit zeroization on encryption and decryption failure branches before returning.

### 9) Passphrase handling created avoidable non-zeroized copy
- Severity: Medium
- Location: `crates/rustynetd/src/key_material.rs`, `crates/rustynet-crypto/src/lib.rs`
- Issue: Passphrase handoff into `KeyCustodyManager` required a plain `String`, creating an avoidable duplicate copy.
- Risk: Sensitive passphrase copy could outlive intended lifetime.
- Fix implemented:
  - Added `KeyCustodyManager::new_zeroizing(...)`.
  - Updated daemon key-material path to pass `Zeroizing<String>` directly into custody manager creation.

### 10) Local IPC client could stall daemon command loop indefinitely
- Severity: Medium
- Location: `crates/rustynetd/src/daemon.rs`
- Issue: Accepted Unix socket streams had no read timeout; a local client could connect and never send a full command line.
- Risk: Single-threaded command loop could block and delay control operations.
- Fix implemented:
  - Added a per-connection read timeout before command ingestion.

### 11) Generated WireGuard private key was not scrubbed if public-key derivation failed
- Severity: High
- Location: `crates/rustynetd/src/key_material.rs`
- Issue: `generate_wireguard_keypair` returned early on `wg pubkey` derivation failure without wiping generated private key bytes.
- Risk: Private key bytes could remain in process memory on failure path.
- Fix implemented:
  - Added explicit private-key zeroization before returning derivation errors.

### 12) Daemon watermark persistence could leave temporary files on failure
- Severity: Medium
- Location: `crates/rustynetd/src/daemon.rs`
- Issue: trust/membership/auto-tunnel watermark persistence wrote temp files atomically but did not clean temp files on write/sync/rename failures.
- Risk: stale temporary state files could accumulate and leave partial sensitive operational state on disk.
- Fix implemented:
  - Added best-effort temp-file cleanup on all failing write/sync/rename branches.
  - Added parent-directory sync after rename for durability.
  - Enforced parent directory mode `0700` during watermark persistence on Unix.

### 13) Control-plane secure state atomic write could leave temporary files on failure
- Severity: Medium
- Location: `crates/rustynet-control/src/lib.rs`
- Issue: `atomic_write_secure` returned on failure without temp-file cleanup.
- Risk: stranded temp trust-state files and residual integrity-state content on disk.
- Fix implemented:
  - Added best-effort temp-file cleanup on write/sync/rename failures.

### 14) Membership and resilience atomic writes could leave temporary files on failure
- Severity: Medium
- Location: `crates/rustynet-control/src/membership.rs`, `crates/rustynetd/src/resilience.rs`
- Issue: atomic-write helpers did not remove temp files when write/sync/rename failed.
- Risk: stale membership/session temp artifacts and increased forensic residue.
- Fix implemented:
  - Added best-effort temp-file cleanup across failure branches.

## Important Design Note
- Trust watermark equality handling (`==`) was evaluated. Enforcing strict `<=` replay rejection caused valid daemon restarts to fail when trust evidence had not changed.
- Current behavior remains `watermark < existing` rejection to preserve restart safety.
- Recommended future hardening path:
  - Persist and validate a signed trust payload digest, then reject equal watermark only when payload differs unexpectedly.

## Verification

### Local (macOS workspace)
- `cargo fmt --all`
- `cargo test -p rustynetd --all-targets`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-targets --all-features`
- `cargo check --workspace --all-targets --all-features`
- `cargo audit --deny warnings`
- `cargo deny check bans licenses sources advisories`

All above passed.

Second hardening pass (additional persistence security fixes) also passed:
- `cargo fmt --all`
- `cargo check --workspace --all-targets --all-features`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-targets --all-features`
- `cargo audit --deny warnings`
- `cargo deny check bans licenses sources advisories`

Additional scope gates executed:
- `./scripts/ci/phase9_gates.sh`
- `./scripts/ci/phase10_gates.sh`
- `./scripts/ci/membership_gates.sh`

Each gate completed lint/build/test/security checks successfully but exited non-zero because required measured Phase 1 performance source evidence file was missing (`performance_samples.ndjson` / equivalent artifact path).

### Debian VM runtime validation (SSH, host `192.168.65.3`)
- Patched files transferred and rebuilt natively on Debian (`cargo build -p rustynetd --release`).
- Installed Linux-native binary to `/usr/local/bin/rustynetd`.
- Re-ran Debian build/test after additional hardening:
  - `cargo fmt --all -- --check`
  - `cargo check -p rustynetd --all-targets`
  - `cargo test -p rustynetd --all-targets`
- During restart validation, daemon correctly failed closed when trust evidence became stale.
- Refreshed signed trust evidence, reset failed unit state, and restarted service.
- Verified active daemon, expected runtime args, and fail-closed SSH allow rule presence.
- Verified fail-closed drop rule idempotence marker exists and does not duplicate across restart.
- Ran Debian-side tests: `cargo test -p rustynetd --all-targets` (pass).
- Second hardening pass on Debian:
  - `cargo fmt --all -- --check`
  - `cargo check --workspace --all-targets --all-features`
  - `cargo test --workspace --all-targets --all-features`
  - `cargo build -p rustynetd --release`
  - Installed updated `/usr/local/bin/rustynetd` and validated runtime nft state.

## Final Runtime State (Debian)
- `rustynetd`: active
- `RUSTYNET_FAIL_CLOSED_SSH_ALLOW=true`
- `RUSTYNET_FAIL_CLOSED_SSH_ALLOW_CIDRS=192.168.65.1/32`
- nft killswitch contains:
  - SSH management allow rule for `192.168.65.1/32`
  - single tagged fail-closed drop rule (`rustynet_fail_closed_drop`)
