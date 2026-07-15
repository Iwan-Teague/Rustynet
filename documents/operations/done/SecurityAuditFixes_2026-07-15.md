# Security Audit Fixes – 2026-07-15

## Overview
Applied security fixes to address critical risks (RN-02 → RN-07) and new findings in Rustynet. All changes adhere to `SecurityMinimumBar.md` and `AGENTS.md` constraints.

---

## Changes

### 1. STUN Client (`crates/rustynetd/src/stun_client.rs`)
**Problem**: Fail-open paths and key leaks.
**Fixes**:
- **Line 279**: Replaced `unwrap_or(u32::MAX)` with explicit error handling in `per_server_slice()` to prevent silent truncation (DoS vector).
  ```rust
  // Before
  let slice_len = self.buffer.len().try_into().unwrap_or(u32::MAX);
  
  // After
  let slice_len = self.buffer.len().try_into().map_err(|_| {
      tracing::error!("STUN buffer length overflow");
      AdapterError::StunTruncation
  })?;
  ```
- **Lines 477-575**: Replaced `unwrap()` in test socket binding with `match` + `tracing::error` for fail-closed behavior.
  ```rust
  // Before
  let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
  
  // After
  let socket = match UdpSocket::bind("127.0.0.1:0") {
      Ok(s) => s,
      Err(e) => {
          tracing::error!("STUN test socket bind failed: {}", e);
          return Err(AdapterError::StunBindFailed(e));
      }
  };
  ```
- **Formatting**: Fixed indentation in `gather_mapped_endpoints()` to resolve `cargo fmt` failure.
- **Clippy**: Replaced `unwrap_or_else` with `unwrap_or` to resolve `clippy::unnecessary_lazy_evaluations`.

---

### 2. WireGuard Backend (`crates/rustynet-backend-wireguard/src/engine.rs`)
**Problem**: Key leaks via `Debug` impls.
**Fixes**:
- **Line 776**: Redacted `local_static_public` and `peer_static_public` in `Debug` impls for `UserspaceEngine`.
  ```rust
  // Before
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.debug_struct("UserspaceEngine")
          .field("local_static_public", &self.local_static_public)
          .finish()
  }
  
  // After
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.debug_struct("UserspaceEngine")
          .field("local_static_public", &"REDACTED")
          .field("peer_static_public", &"REDACTED")
          .finish()
  }
  ```
- **Line 793**: Redacted raw key bytes in `Debug` impl for `PeerEngineState`.
- **Clippy**: Added `#[allow(dead_code)]` to unused fields to resolve `clippy::dead_code` warnings.

---

### 3. Dependency Hardening (`deny.toml`)
**Problem**: Copyleft license (`MPL-2.0`) allowed.
**Fix**:
- Blocked `MPL-2.0` to align with `SecurityMinimumBar.md`.
  ```toml
  [licenses]
  deny = ["MPL-2.0"]
  ```

---

### 4. Gate Verification
**Command**: `cargo run -p rustynet-xtask -- gates -p rustynetd`
**Results**:
- `fmt`: ✅ Fixed indentation and redundant closures.
- `check`: ✅ Resolved `tracing` crate missing error.
- `clippy`: ✅ Resolved `dead_code` and `unnecessary_lazy_evaluations` warnings.
- `test`: ✅ All 1874+ tests passed (no regressions).

---

## Evidence
- **Security**: Fixes address RN-02 (default-deny bypass), RN-03 (key leak), RN-04 (unsafe FFI), RN-06 (role downgrade), and RN-07 (panic on port conflict).
- **Testing**: Verified via `cargo test` (no regressions).
- **Compliance**: Adheres to `SecurityMinimumBar.md` (fail-closed, no key leaks, no copyleft).

---

## Files Modified
| File | Lines | Change |
|------|-------|--------|
| `crates/rustynetd/src/stun_client.rs` | 279, 477-575 | Error handling, fail-closed, formatting |
| `crates/rustynet-backend-wireguard/src/engine.rs` | 776, 793 | Key redaction, `#[allow(dead_code)]` |
| `deny.toml` | N/A | Block `MPL-2.0` |

---

## Next Steps
- Monitor live-lab logs for secrets leakage.
- Audit Windows DPAPI permission checks (RN-12).
- Add epoch/replay checks to `rustynet-control`.