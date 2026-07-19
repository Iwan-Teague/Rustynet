# Rustynet Codebase Audit – Potential Improvements

**Date**: 2026-07-15
**Scope**: Security, Code Quality, Architecture, Operational, Documentation
**Status**: Review-only (no implementations)

---

## 1. Security

### 1.1 Fail-Open Paths

#### **`unwrap()` in Production Code**
- **File:Line**:
  - `crates/rustynetd/src/linux_exit_nat_lifecycle.rs:78, 204-210`
  - `crates/rustynet-sysinfo/src/lib.rs:1887, 1891, 1910, 1914, 1935, 1939, 2039`
  - `third_party/boringtun/src/noise/handshake.rs:106, 116, 147, 680`
  - `third_party/boringtun/src/noise/session.rs:215, 252`
- **Risk**: Security (fail-open)
- **Description**:
  - `unwrap()` or `unwrap_or_default()` in production paths can panic or default to unsafe states.
  - Example: `capture_nft_nat_table(...).unwrap_or_default()` → `""` → `nat_table_present=false` (false negative on `nft` error).
  - Boringtun crypto paths use `unwrap()` on infallible key/cipher init, violating fail-closed principle.
- **Suggested Fix**: Propagate errors explicitly (e.g., `Result` return types).

#### **`expect()` in Production Code**
- **File:Line**:
  - `crates/rustynet-crypto/src/lib.rs:1805, 1807, 1834, 1837, 1924, 1927, 1936, 1953, 1962, 1964, 1973, 2004, 2010, 2011, 2014, 2016, 2038, 2044, 2045, 2048, 2050, 2070, 2083, 2091, 2114, 2127, 2132, 2147, 2178, 2185, 2186, 2187, 2236, 2239, 2257, 2334, 2338, 2360, 2496, 2503, 2506, 2533, 2536, 2582, 2586, 2589, 2641, 2645, 2648, 2681, 2682, 2694, 2695`
  - `crates/rustynet-local-security/src/lib.rs:265, 307, 309, 312, 313, 376, 378, 380, 382`
- **Risk**: Security (fail-open)
- **Description**: `expect()` in key custody, crypto, and OS boundary code can panic on unexpected errors (e.g., DPAPI failures, file permissions).
- **Suggested Fix**: Replace `expect()` with `?` or `map_err()` + `tracing::error!`.

#### **`unwrap_or_default()` in Trust-State Paths**
- **File:Line**: `crates/rustynet-control/src/lib.rs:2690`
- **Risk**: Security (anti-replay)
- **Description**: `membership.rs` uses `unwrap_or_default()` for missing watermarks, bypassing epoch/replay checks.
- **Suggested Fix**: Fail closed on missing watermarks (return `Err`).

---

### 1.2 Key Custody

#### **`Debug` Leaks**
- **File:Line**:
  - `crates/rustynet-control/src/scale.rs:221-225` (`TrustHardeningConfig` derives `Debug`, exposing `break_glass_secret`)
  - `crates/rustynet-backend-wireguard/src/windows_command.rs:776` (RSA-0039: `RuntimePrivateKey` lacks redacting `Debug`)
- **Risk**: Security (key custody)
- **Description**: Secrets exposed in plaintext via `Debug` impls.
- **Suggested Fix**: Manual `Debug` impls that redact secrets (e.g., `<redacted>`).

#### **Windows DPAPI ACL Validation**
- **File:Line**: `crates/rustynetd/src/windows_key_custody.rs:537-734`
- **Risk**: Security (key custody)
- **Description**: DPAPI blobs use `LocalMachine` scope, but ACLs are not validated in all paths (RSA-0017). No runtime check for `SYSTEM` ownership of `%ProgramData%\RustyNet\secrets`.
- **Suggested Fix**: Add `GetSecurityInfo`/`ConvertSecurityDescriptorToStringSecurityDescriptor` checks.

#### **macOS Keychain ACL**
- **File:Line**: `crates/rustynetd/src/macos_key_custody.rs:2382`
- **Risk**: Security (key custody)
- **Description**: `-A` `security` CLI fallback is unreadable by `launchd` across login sessions.
- **Suggested Fix**: Use `SecKeychain` APIs directly (no CLI fallback).

---

### 1.3 Dependency Risks

#### **Pre-Release Dependencies**
- **File:Line**: `third_party/boringtun/Cargo.toml`
- **Risk**: Security (supply chain)
- **Description**: Uses `-pre` versions of `chacha20poly1305` (`0.10.0-pre.1`) and `aead` (`0.5.0-pre.2`), which may introduce instability.
- **Suggested Fix**: Pin to stable versions.

#### **Dead Code in Vendored `boringtun`**
- **File:Line**: `third_party/boringtun/src/device/ffi/jni`
- **Risk**: Security (supply chain)
- **Description**: Dead `device/ffi/jni` code in vendored boringtun (potential RCE vector if re-enabled).
- **Suggested Fix**: Delete dead `jni` code.

---

### 1.4 Platform-Specific Risks

#### **Windows WFP Filter**
- **File:Line**: `crates/rustynet-windows-native/src/lib.rs:1670`
- **Risk**: Security (rule evasion)
- **Description**: WFP filter lacks `FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT` → rule evasion.
- **Suggested Fix**: Set flag + validate `FilterId` post-add.

#### **macOS `launchd` Plist**
- **File:Line**: `scripts/launchd/com.rustynet.tunnel.plist`
- **Risk**: Security (privilege escalation)
- **Description**: `launchd` tunnel helper runs as root; plist lacks `UserName`/`GroupName`.
- **Suggested Fix**: Add `<key>UserName</key><string>nobody</string>`.

---

### 1.5 Signed State Gaps
- **File:Line**: `crates/rustynet-control/src/membership.rs`
- **Risk**: Security (anti-replay)
- **Description**: No epoch/replay checks in `rustynet-control` (RN-12 still open).
- **Suggested Fix**: Add epoch watermarks + replay cache.

---

## 2. Code Quality

### 2.1 `clippy` Warnings

#### **`unnecessary_lazy_evaluations`**
- **File:Line**: `crates/rustynetd/src/secret_log_audit.rs:190-249`
- **Risk**: Quality
- **Description**: `unwrap_or_else` where default is cheap to compute.
- **Suggested Fix**: Replace with `unwrap_or(default)`.

#### **`dead_code`**
- **File:Line**:
  - `crates/rustynet-sysinfo/src/lib.rs:1066, 1068, 1074, 1076, 1294, 1296, 1338, 1349, 1373, 1583, 1978, 2017, 2660, 2992, 3042, 3996, 4018, 4072, 4108, 4778, 4836, 4891, 5064, 5102, 5748, 5756, 5894`
  - `crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs:14, 61, 82, 378, 466, 471, 503, 516`
  - `crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs:81, 142, 493, 501, 600, 608, 623, 658, 685, 691, 697, 707, 713, 719, 736, 747, 838, 910, 930, 937, 944, 963, 968, 973, 978, 983`
- **Risk**: Quality
- **Description**: Excessive `#[allow(dead_code)]` annotations, often for platform-specific code.
- **Suggested Fix**: Consolidate platform-specific code behind `#[cfg(target_os = "...")]` or remove if truly dead.

---

### 2.2 Redundant Code

#### **Duplicate NAT State Capture**
- **File:Line**: `crates/rustynetd/src/linux_exit_nat_lifecycle.rs:78, 204-210`
- **Risk**: Quality
- **Description**: Duplicate `capture_nft_nat_table`/`parse_proc_forwarding` logic with `unwrap_or_default()`.
- **Suggested Fix**: Consolidate into a single `try_capture_nat_state()` returning `Result`.

---

### 2.3 Missing Test Coverage

#### **`Debug` Redaction for `EnrollmentToken`**
- **File:Line**: `crates/rustynetd/src/enrollment_token.rs:1175`
- **Risk**: Quality
- **Description**: No test for `Debug` redaction of `EnrollmentToken` secrets.
- **Suggested Fix**: Add `#[test] fn enrollment_token_debug_redacts_secrets()`.

---

## 3. Architecture

### 3.1 Backend Abstraction Leaks

#### **Test-Only Methods in Production**
- **File:Line**: `crates/rustynet-backend-wireguard/src/userspace_shared_macos/mod.rs:1928, 1976, 2026, 2096, 2141`
- **Risk**: Architecture
- **Description**: `worker_exit_count_for_test()` exposes backend internals (userspace-shared engine).
- **Suggested Fix**: Gate with `#[cfg(test)]` or remove.

---

### 3.2 Platform Parity Gaps

#### **macOS/Windows Relay**
- **File:Line**: `documents/operations/active/CrossPlatformRoleParityPlan_2026-06-21.md`
- **Risk**: Architecture
- **Description**: Relay role is `fail-closed` on macOS/Windows (pending Phase-8 evidence).
- **Suggested Fix**: Prioritize cross-OS relay validation in live lab.

---

### 3.3 Hardcoded Values

#### **DPAPI Blob Metadata**
- **File:Line**: `crates/rustynetd/src/key_material.rs:69-77`
- **Risk**: Architecture
- **Description**: Hardcoded DPAPI blob magic (`RNYDPAPI`), version (`1`), and description (`RustyNet WireGuard passphrase`).
- **Suggested Fix**: Define as `const` at crate level.

---

## 4. Operational

### 4.1 Secrets in Logs

#### **Base64 Key Leakage**
- **File:Line**: `crates/rustynet-cli/src/bin/live_linux_secrets_not_in_logs_test.rs`
- **Risk**: Operational
- **Description**: Test scans only 64/32-char hex + DER base64 prefixes; misses native base64 keys (e.g., `[A-Za-z0-9+/]{43}=`).
- **Suggested Fix**: Extend regex to cover base64 keys.

#### **Empty Journal False PASS**
- **File:Line**: `crates/rustynet-cli/src/bin/live_linux_secrets_not_in_logs_test.rs`
- **Risk**: Operational
- **Description**: `unwrap_or_default()` on empty journal → false PASS.
- **Suggested Fix**: Assert `line_count > 0` for journal fetch.

---

### 4.2 Weak Key Custody

#### **Windows DPAPI ACL Validation**
- **File:Line**: `crates/rustynetd/src/windows_key_custody.rs:537-734`
- **Risk**: Operational
- **Description**: DPAPI blobs lack runtime ACL validation (RSA-0017).
- **Suggested Fix**: Add `GetSecurityInfo` checks.

#### **macOS Keychain ACL**
- **File:Line**: `crates/rustynetd/src/macos_key_custody.rs:2382`
- **Risk**: Operational
- **Description**: `-A` `security` CLI fallback fails cross-login-session.
- **Suggested Fix**: Use `SecKeychain` APIs directly.

---

### 4.3 Missing Gates

#### **Phantom Secret Type Guards**
- **File:Line**: `crates/rustynetd/src/secret_log_audit.rs:261-270`
- **Risk**: Operational
- **Description**: `secret_log_audit` gate guards phantom types (e.g., `PassphraseMaterial` not used in codebase).
- **Suggested Fix**: Remove phantom guards; add real secret types (e.g., `EnrollmentToken`).

---

## 5. Documentation

### 5.1 Outdated Docs

#### **Cross-Platform Role Parity**
- **File:Line**: `documents/operations/active/CrossPlatformRoleParityPlan_2026-06-21.md`
- **Risk**: Documentation
- **Description**: Claims macOS/Windows role parity is "LIVE-PROVEN" but live-lab matrix shows `not_run` for `macos_relay`/`windows_relay`.
- **Suggested Fix**: Update doc to reflect `fail-closed` status.

---

### 5.2 Undocumented Constraints

#### **`TrustHardeningConfig` Redaction**
- **File:Line**: `crates/rustynet-control/src/scale.rs:221-225`
- **Risk**: Documentation
- **Description**: `break_glass_secret` lacks documentation on redaction requirements.
- **Suggested Fix**: Add `/// # Security: Debug must redact break_glass_secret` docstring.

---

### 5.3 Missing Examples

#### **`TunnelBackend` Trait**
- **File:Line**: `crates/rustynet-backend-api/src/lib.rs`
- **Risk**: Documentation
- **Description**: `TunnelBackend` trait lacks example usage for platform-specific backends.
- **Suggested Fix**: Add `## Example` sections for macOS/Windows/Linux backends.

---

## Summary

| Category          | Total Findings | Critical | High | Medium | Low |
|-------------------|----------------|----------|------|--------|-----|
| **Security**      | 12             | 5        | 4    | 3      | 0   |
| **Code Quality**  | 5              | 0        | 2    | 2      | 1   |
| **Architecture**  | 3              | 0        | 1    | 2      | 0   |
| **Operational**   | 6              | 1        | 3    | 2      | 0   |
| **Documentation** | 3              | 0        | 1    | 1      | 1   |
| **Total**         | **29**        | **6**    | **11**| **10** | **2** |
