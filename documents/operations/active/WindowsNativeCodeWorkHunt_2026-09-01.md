# Windows-Native Code Work Hunt — 2026-09-01

**Scope:** docs-only sweep of `crates/rustynet-windows-native/` (the single-file Windows OS-boundary crate: WFP firewall, DPAPI key custody, named-pipe IPC, Authenticode, SDDL inspection). No `.rs` files were changed. Survey performed in worktree branch `ai-edit/edit-1788297638455-45994-21` at HEAD `f2661526` (clean tree at survey start). This closes the gap `RepoCodeWorkHunt_2026-09-01.md` §"Honest limits" explicitly left: "`rustynet-windows-native` was not included in the per-file unwrap re-count sweep."

**Honest headline: the crate is clean at P1/P2.** All six hunt categories were swept with per-hit open-and-read verification over the full file (`src/lib.rs`, 2931 lines; production code is lines 1–2423, with three `#[cfg(test)]`/`#[cfg(windows)] #[cfg(test)]` modules after that). No markers, no panicking `unwrap()`/`expect()` on any production path, no fail-open verdicts, no secret-material logging, no process spawning at all (the crate's whole design is native FFI replacing PowerShell), and the WFP/NAMED-PIPE security logic is fail-closed with drift pins and tests. Three P3s are recorded below: one doc-comment asserting a Windows implementation that does not exist on any platform, one dead production helper behind a blanket `allow(dead_code)`, and one error-path handle leak. All three are small, offline-fixable, and none needs adversarial review.

## Method and dedup

The entire file was read end-to-end, not grep-sampled, because the crate is one translation unit. Every grep hit in every category was then re-located and read in context before judgment; test code was separated from production code using the `#[cfg(test)]` boundary (production ends at line 2423 where `wfp_filter_shape`'s `#[cfg(test)] mod tests` begins; the top-level `mod tests` starts at `:2760` and `token_filter_tests` at `:2849-2850`). Only production-path instances were counted.

Already-tracked territory excluded per the dedup requirement:

- `QualityHardeningTodo_2026-07-25.md` (QH-01..QH-64) — the Windows-native-relevant items (QH-46 forwarded-traffic WFP assertion, QH-57-class WFP management-allow question at `:5924-5936`) are tracked and were not re-raised.
- `FullTodoInventory_2026-07-28.md` — notably WIN-1 (confirmed-sound, not a finding), WIN-2/3 (perf catalog: subprocess-per-item + DPAPI re-encrypt, no TCP_NODELAY), the TOCTOU note on `validate_secret_file_security` (`:545`), and **`:573`: "W5: Win32 FFI signer-thumbprint extraction body — needs live Windows fixture, explicitly not safe to land from non-Windows"** — the *missing Windows body* of the thumbprint extractor is tracked; finding F-1 below is only about the lib-level doc asserting the opposite of what exists.
- `RepoCodeWorkHunt_2026-09-01.md` — method template and the F-1/F-2 siblings in other crates.
- The `rustynet-security-auditor` skill catalog (`tools/skills/rustynet-security-auditor/`) — grepped for `windows-native`/`DPAPI`/`named pipe`/`WFP`; zero hits, so nothing in the crate is catalog-tracked.

## Findings (ranked)

### WIN-F-1 (P3) — Lib-level doc comment asserts a Windows thumbprint implementation that exists on no platform

- **Where:** `crates/rustynet-windows-native/src/lib.rs:128-144` (doc on the off-Windows stub) vs. the Windows-side body at `:574-600`.
- **The drift.** The public doc says: *"On Windows the implementation calls `CryptQueryObject` to open the PE's signature blob, walks the CMS SignerInfo via `CryptMsgGetParam(...)` ... and reads `CertGetCertificateContextProperty(CERT_SHA256_HASH_PROP_ID)`. Returns the lowercase hex of the 32-byte SHA-256 hash."* The actual `#[cfg(windows)]` body is a typed reject:

  ```rust
  pub fn extract_signer_thumbprint_sha256(_path: &Path) -> Result<String, String> {
      Err(
          "Windows Authenticode thumbprint extractor pending validation on a Windows fixture; \
           treat as fail-closed via evaluate_thumbprint_policy(None, &policy)"
              .to_owned(),
      )
  }
  ```

  (`lib.rs:594-600`.) The impl's own doc (`:574-589`) honestly explains the Win32 surface "has not yet been validated against a Windows runtime fixture", but the *lib-level* doc a reader hits first describes behavior that exists nowhere. Behavior is safe — the caller in `crates/rustynetd/src/windows_authenticode.rs:343-361` documents that extraction yields `None` on every host and `evaluate_thumbprint_policy` fail-closes whenever a policy is supplied — so this is drift plus an availability trap (a thumbprint-pinned policy can never pass today), not a bypass.
- **Why it matters:** an operator reading the crate surface would conclude Windows thumbprint pinning works and debug the wrong layer when every pinned-binary check drifts; doc-comment-vs-behavior drift is hunt category 6 and the crate's only instance.
- **Proposed offline fix:** rewrite `:128-144` to state the truth — the Windows body is also a fail-closed placeholder pending fixture validation, the extraction is permanently `Err` today, and `evaluate_thumbprint_policy(None, &policy)` is the resulting verdict — mirroring the honest framing the `:146-159` `verify_authenticode_chain` stub already uses. Comment-only change.
- **Offline-fixable:** yes. **Needs adversarial review:** no. **Dedup note:** the missing implementation body itself is already tracked (`FullTodoInventory_2026-07-28.md:573`); only the doc claim is new here.

### WIN-F-2 (P3) — Dead production helper permanently suppressed by a blanket `#[allow(dead_code)]`

- **Where:** `crates/rustynet-windows-native/src/lib.rs:1393-1431`.

  ```rust
  #[allow(dead_code)]
  fn inspect_handle_sddl(handle: HANDLE) -> Result<String, String> {
      ...GetKernelObjectSecurity... -> security_descriptor_to_sddl(...)
  }
  ```

- **Why it matters:** a kernel-object SDDL reader with zero call sites anywhere in the repo (verified by repo-wide grep: the only references are the definition itself and nothing else) sits behind a suppression that will keep it compiling — and keep it exempt from the unused-code signal — forever. This is the same class as the prior hunt's F-2 (whole-file `allow(dead_code)` on two macOS backend files), which explicitly did not sweep this crate. The sibling allow pattern used elsewhere in the workspace is the per-item cross-platform `#[cfg_attr(not(windows|test), allow(dead_code))]`, which at least documents *why* an item is conditionally unused; a bare `#[allow(dead_code)]` on a Windows-only function documents nothing, because on Windows it is simply dead.
- **Proposed offline fix:** delete `inspect_handle_sddl` (the one-path discipline favors removal; the file/pipe/registry SDDL readers are the live surfaces), or, if the Windows fixture work is expected to consume it soon, replace the blanket allow with a `#[cfg_attr(not(test), allow(dead_code))]` plus a comment naming the consuming slice.
- **Offline-fixable:** yes. **Needs adversarial review:** no.
- **Resolved 2026-09-02:** deleted; zero call sites. `GetKernelObjectSecurity` import removed with it (used by nothing else); all sibling SDDL readers (file/pipe/registry) untouched.

### WIN-F-3 (P3) — `owned_pwstr_to_string` leaks the Win32-allocated buffer when UTF-16 decoding fails

- **Where:** `crates/rustynet-windows-native/src/lib.rs:1243-1258`.

  ```rust
  fn owned_pwstr_to_string(ptr: *mut u16) -> Result<String, String> {
      if ptr.is_null() { return Err(...); }
      let mut len = 0usize;
      unsafe {
          while *ptr.add(len) != 0 { len += 1; }
          let slice = std::slice::from_raw_parts(ptr, len);
          let value =
              String::from_utf16(slice).map_err(|err| format!("UTF-16 decode failed: {err}"))?;
          LocalFree(ptr.cast::<c_void>());
          Ok(value)
      }
  }
  ```

- **Why it matters:** on the `from_utf16` error path the function returns before `LocalFree(ptr)`, leaking the `LocalAlloc`'d buffer for every owned wide-string the Windows API hands back (SDDL strings via `security_descriptor_to_sddl`, SID strings via `sid_to_string` — i.e. every SDDL inspection and every token-group conversion). It is a malformed-API-output-only, tiny-buffer, one-shot leak — a robustness blemish, not a fail-open and not a DoS at realistic rates — but the fix is mechanical and the function is the single funnel for all owned-string returns.
- **Proposed offline fix:** decode into a variable, `LocalFree` unconditionally, then return the decode result (e.g. compute `value = String::from_utf16(slice)`, call `LocalFree` on both paths — `let result = String::from_utf16(...); unsafe { LocalFree(...) }; result.map_err(...)`).
- **Offline-fixable:** yes. **Needs adversarial review:** no (no security-semantics change; the same string is returned either way).

## Cleared with evidence (so the next hunt does not re-read this ground)

- **Markers (cat 1):** zero hits — no `TODO`/`FIXME`/`XXX`/`HACK`/`unimplemented!(`/`todo!(`/`unreachable!` anywhere in the file, production or test.
- **unwrap/expect (cat 2):** the only non-test hits are two benign fallbacks, read in context: `lib.rs:1000` `u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX)` — a saturation clamp on the client-side `CallNamedPipeW` timeout, not a panic, and a giant timeout is the caller's own request; and `lib.rs:779` `facts.user_sid.as_deref().unwrap_or("<unknown>")` — a display fallback inside the unauthorized-client rejection message. No `.unwrap()` and no `.expect()` exists on any production path; every FFI result is checked and mapped to `Err` with the Windows error code (`GetLastError` captured immediately after each failing call). Test-only expects at `:2486`, `:2802`, `:2824` are inside `#[cfg(test)]` modules.
- **Fail-open shapes (cat 3):** every candidate read and dismissed:
  - `lib.rs:1507-1513` `let _ = WinVerifyTrust(...WTD_STATEACTION_CLOSE...)` — the mandated state-cleanup follow-up whose result is intentionally discarded; the primary `verify_status` verdict at `:1515` is what callers see. Correct per the Win32 contract, documented at `:1442-1446`.
  - `lib.rs:1911-1918` `filter_map(|alias| interface_alias_to_luid(alias).ok()...)` in `wfp_tunnel_permit_present` — an unresolvable *forbidden* alias is skipped, but the doc comment at `:1909-1911` states why that is safe and the code confirms it: the tunnel-LUID equality check at `:2261` still rejects any filter whose condition is not exactly the tunnel, so the skip only forgoes a more specific error label, never the verdict.
  - `lib.rs:481-488` `RegCloseKey` result ignored — documented benign (verdict already extracted; close failure is a kernel handle-table oddity, not a trust input).
  - `lib.rs:832-838` `ImpersonationGuard::drop` ignores `RevertToSelf()`'s return — `Drop` cannot propagate, `RevertToSelf` on an impersonated thread does not fail in practice, and the guard wraps only the token-inspection window (`:817-827`). Residual risk accepted, noted here so it is a recorded decision rather than an oversight.
  - `lib.rs:1191-1196` `write_pipe_message` maps `FlushFileBuffers` `ERROR_BROKEN_PIPE` to `Ok(())` — a vanished client cannot be notified and the handler already ran; deliberate best-effort reply teardown per the comment at `:794-802`.
  - `lib.rs:1260-1272` / `:1274-1281` null wide/narrow string → empty `String` — used only for adapter naming (`:1068-1070`), where `display_name()` (`:26-34`) falls through friendly → adapter → description; no trust decision reads these.
  - WFP shape validation (`wfp_filter_shape::validate_tunnel_permit_shape`, `:2213-2268`) rejects on *every* deviation — wrong action, zero or multiple conditions (zero conditions on a hard permit = permit-all, explicitly the dangerous case), wrong field key, wrong value encoding, non-maximal or auto weight, LUID pointing at a forbidden NIC, plain LUID mismatch — and a filter *present but malformed* is `Err` (`:1900-1902`), never mistaken for the safe missing case. A missing filter is `Ok(false)` = tunnel blocked = fails safe.
  - Forwarded-traffic arbitration (`:2404-2422`) — unreadable WFP state maps to `ForeignForwardObstruction::Unreadable` (fail-closed, mirroring the Linux firewalld unknown-presence rule, `:2349-2356`), any action that is not positively `FWP_ACTION_PERMIT` is an obstruction (`:2413-2419`), and only filters under our own sublayer key are exempt (`:2409-2411`, documented at `:2308-2319`). The QH-46 Windows enforcement point (`:2017-2030`) converts any obstruction into the caller's fail-closed rollback.
  - Read-back hardening: null condition array with non-zero count refused (`:1816-1819`), null `FWP_UINT64` pointers refused (`:1830-1841`, `:1857-1867`), declared condition counts never replayed as allocation size (`reduce_readback_conditions`, `:2290-2306`, bound `MAX_MATERIALIZED_CONDITIONS = 16` with tests `:2587-2627`), compile-time drift pins against the portable constants (`:1780-1787`, `:1949-1957`).
  - Named-pipe authorization: connect is gated by the pipe's SDDL + `PIPE_REJECT_REMOTE_CLIENTS` (`:735`, rationale `:83-90`), the client token facts are extracted with the UAC filter — `SE_GROUP_ENABLED` AND NOT `SE_GROUP_USE_FOR_DENY_ONLY` (`:901-910`, tests `:2867-2930` catch DENY_ONLY/disabled/both-bits Administrators SIDs) — and the verdict is allow-if-`(LocalSystem | builtin-admin | service-identity)` (`:806-811`), with unauthorized clients force-disconnected (`:774-784`). The pre-authorization read (`:762-770`) is the documented Windows impersonation requirement and the bytes are not passed to the handler until authorization passes.
  - DPAPI (`:349-410`): empty-input rejection both directions, every failure path returns `Err` with only the Windows error code — the blob/plaintext bytes are never formatted, logged, or `Debug`-printed anywhere in the crate (cat 4: zero `println!`/`tracing`/`dbg!`/`log::` hits). `blob_to_vec` (`:1298-1310`) frees the API buffer and nulls the fields; residual key-material lifetime in the returned `Vec<u8>` is the caller's custody concern, consistent with the SecurityMinimumBar split.
- **argv-only exec discipline (cat 5):** zero process-spawning surface in the crate — no `Command`, `process::`, `powershell`, or shell-string construction hits at all. The WFP tunnel-permit section (`:1555-1560`) exists precisely to remove the last PowerShell/WMI call from the dataplane path ("No PowerShell/WMI, so it cannot hang on a wedged WMI provider").
- **Doc-drift (cat 6):** the remaining doc comments spot-checked match behavior: `verify_authenticode_chain` (`:1433-1446` — cleanup even on error, implemented at `:1504-1513`), `inspect_registry_key_sddl` (`:111-122`, `:451-472`), the `PIPE_REJECT_REMOTE_CLIENTS` remote-rejection comment (`:83-90`, flag at `:735`), `wfp_delete_objects` ordering (filters-then-sublayer, `:1620-1638`), and the sublayer-exemption rationale for the forward-layer scan (`:2308-2319`). The single drift is WIN-F-1 above.
- **Cross-check against callers:** the thumbprint stub's one consumer (`crates/rustynetd/src/windows_authenticode.rs:343-361`) honestly documents the always-`None`-fail-closed reality in situ, so no caller-side drift compounds WIN-F-1.

## Honest limits of this pass

- The `#[cfg(windows)]` FFI bodies were reviewed by reading, not by execution — no Windows host was exercised, and no gates were run (docs-only survey; no code changed). All claims are read-level observations with file:line citations, same as the parent hunt.
- `unsafe` correctness beyond the hunted categories (e.g. pointer lifetime discipline in `wfp_add_permit_filter`, which pins its locals deliberately and documents why at `:1661-1665`) was spot-checked, not exhaustively audited; a dedicated unsafe/FFI audit of this crate would be the natural next deep pass.
- The callers of this crate outside `windows_authenticode.rs` (daemon IPC, killswitch wiring) were consulted only where needed to judge blast radius; the daemon side remains swept only by the parent hunt.

## Suggested next steps

1. Fold WIN-F-1 (doc rewrite), WIN-F-2 (delete-or-gate the dead helper), and WIN-F-3 (free-before-error) into the next hygiene pass on this crate; none warrants its own change on urgency, and all three are mechanical.
2. Keep WIN-F-1's underlying item pointed at the tracked Windows-fixture work (`FullTodoInventory_2026-07-28.md:573`) — the doc should be corrected now so it stops describing an implementation that has never existed, and the real body lands later without touching the doc again.
3. With this sweep, the parent hunt's un-sampled list shrinks to the systematic doc-drift audit and the hot-path clone audit.
