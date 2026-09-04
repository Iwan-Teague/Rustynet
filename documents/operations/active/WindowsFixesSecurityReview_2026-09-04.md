# Windows Fixes Security Review — 2026-09-04

**STATUS: UNTRUSTED — MACHINE-GENERATED ADVERSARIAL REVIEW (docs-only, no code changed).** This document was produced by an AI review agent in an isolated worktree (`ai-edit/edit-1788558344537-26537-23`). Every finding below must be independently verified against the cited code before it drives any action. Do not treat any classification here as certified evidence.

**Reviewed commits:**
- `f454cbd8` — `fix(sysinfo): add missing Windows arm for apparmor_profile_status_internal`
- `77262024` — `fix(crypto): implement Windows SDDL key-custody permission validation (CRY-05)`

**Files under review:**
- `crates/rustynet-sysinfo/src/lib.rs` (8594 lines)
- `crates/rustynet-crypto/src/lib.rs` (4993 lines)

**Method:** full read of both changed regions plus a structural audit of every `*_internal` function's `cfg` arms in the sysinfo crate, and an adversarial walk of the Windows key-custody permission path against the questions (a)–(d) in the review brief. Line numbers refer to the files at the reviewed commits.

---

## Fix 1 — `apparmor_profile_status_internal` Windows arm (f454cbd8)

### F1.1 — CONFIRMED-SAFE: the fix adds the missing Windows arm; it was the sole omission of its class

`apparmor_profile_status_internal` now has exactly three definitions in `crates/rustynet-sysinfo/src/lib.rs`:

- `src/lib.rs:5202` — `#[cfg(target_os = "linux")]` (real check)
- `src/lib.rs:5240` — `#[cfg(target_os = "macos")]` (empty-Vec placeholder)
- `src/lib.rs:5249` — `#[cfg(target_os = "windows")]` (empty-Vec placeholder, the fix)

The new Windows arm returns an empty `Vec`, matching the macOS placeholder convention: AppArmor is a Linux-only feature, so "no AppArmor findings" is the correct no-op on non-Linux, not a fail-open of a real control.

A structural audit of all 89 `*_internal` functions in the crate was performed to test the commit's claim that "every other `*_internal` fn already has all three arms":

- 40 functions have the full 3-arm `target_os = {linux, macos, windows}` pattern (e.g. `git_version_internal` at 1009/1017/1024, `memory_info_internal` at 2515/2580/2622, `socket_stats_internal` at 2861/2931/2987 — full list held in the review session notes).
- The remainder are single-definition functions whose bodies carry internal `cfg` arms (e.g. `security_checks_internal` at 1349, `interface_stats_internal` at 2334 with linux + `cfg(not(linux))`), which compile on all three OSes.
- The one function that is neither 3-arm nor single-definition — `ipc_socket_responsiveness_internal` — has exactly two defs at `src/lib.rs:6164-6212`: a `#[cfg(target_family = "unix")]` real probe (6165-6201) and a `#[cfg(not(target_family = "unix"))]` placeholder (6203-6212). This is complete coverage; Windows compiles; not a gap.

Conclusion: the commit message claim holds. `apparmor_profile_status_internal` was the only function of the 3-arm style missing a Windows arm, and no other function is structurally missing an arm such that Windows fails to compile. This is consistent with the commit's own verification (`cargo check --target x86_64-pc-windows-gnu`, exit 0).

---

## Fix 2 — Windows SDDL key-custody permission validation (77262024)

Background: `validate_key_custody_permissions` (`crates/rustynet-crypto/src/lib.rs:1851`) previously failed closed on Windows with `PermissionValidationUnavailable` via a `#[cfg(not(unix))]` stub, which blocked `rustynetd key init` on Windows. The new `#[cfg(windows)]` arm (`src/lib.rs:1888-1911`) calls two validators:

- `validate_windows_dpapi_root` (`src/lib.rs:1048-1063`): rejects symlinks and non-directories (`PermissionDenied`); fails closed on SDDL read error (`PermissionValidationUnavailable`); requires the directory DACL string to contain `D:P` (protected DACL) and rejects any ACE containing `;;;WD)` (Everyone), `;;;AU)` (Authenticated Users), or `;;;BU)` (Builtin Users).
- `validate_windows_dpapi_file` (`src/lib.rs:1065-1080`): rejects symlinks and non-files; fails closed on SDDL read error; requires the DACL to contain `D:` and rejects the same three broad-SID ACEs.

The narrowed refuse stub for other platforms is `#[cfg(not(any(unix, windows)))]` (`src/lib.rs:1913-1935`) and still returns `Err(PermissionValidationUnavailable)`.

### F2.a — CONFIRMED-SAFE (within its stated model): the Windows arm cannot return `Ok` on an ACL that exposes the key to broad groups

`Ok` requires all of: directory is a real directory (not symlink), its SDDL read succeeds, its DACL is protected (`D:P`), no WD/AU/BU ACE on the directory, the key file is a real file, its SDDL read succeeds, it has a DACL, and no WD/AU/BU ACE on the file. Any deviation yields `PermissionDenied` or `PermissionValidationUnavailable` — the arm never defaults to allow and never ignores a read error. Within the model "insecure = exposed to Everyone/Authenticated Users/Builtin Users", the arm cannot approve an insecure ACL.

The two caveats that qualify this are F2.b (strictness asymmetry) and F2.c (raw-SID bypass), which narrow the model rather than break it.

### F2.b — POTENTIAL-WEAKNESS (moderate): strictness asymmetries vs. the unix owner-only arm

The unix arm enforces owner-only mode bits (`0o700`/`0o600`) with an owner-uid match, confining access to the effective user. The Windows arm has two asymmetries against that bar:

1. **File DACL protection not required** — `validate_windows_dpapi_file` (`src/lib.rs:1065-1080`) requires only `D:`, not `D:P`. A file with a non-protected DACL (inherited ACEs active) passes as long as no WD/AU/BU ACE is present. Mitigation: the file lives inside the `D:P`-protected directory validated first, and inheritance from that directory is the expected source of its ACEs. Still, the file-level check alone is weaker than the directory-level one; if the file is ever relocated or the directory check is bypassed, the file check will not catch a non-protected DACL.
2. **No owner-SID assertion** — neither Windows validator checks that the DACL's owner/trustee set is confined to the current user (plus SYSTEM/Administrators, which the arm's comment at `src/lib.rs:1898-1899` accepts by design). A narrow ACE explicitly granting another specific user full control would pass both validators, whereas the unix owner+mode check rejects any such configuration implicitly. The Windows arm therefore verifies "no broad access" but not "owner-only access".

Neither asymmetry lets a *broadly readable* key pass; both are cases where a *narrowly over-permissive* configuration is accepted. Recommend (non-blocking, follow-up): require `D:P` on the file as well, and consider asserting the owner SID equals the current user.

### F2.c — POTENTIAL-WEAKNESS / QUESTION: broad-SID rejection is literal-string on three SDDL acronyms; raw-SID principals bypass it

The checks are substring matches for `";;;WD)"`, `";;;AU)"`, `";;;BU)"`. SDDL also permits principals expressed as raw SIDs, so a DACL string containing `(A;;FA;;;S-1-1-0)` — Everyone expressed as its SID instead of the `WD` acronym — contains none of the three markers and passes the validator while granting access to Everyone. The same applies to other wide principals not in the rejected set, e.g. `CO` (Creator Owner, meaningful on inheritable ACEs), `NU` (Network logon), `RC`/`WR` (Restricted/World restricted code), `S-1-5-12`, and machine-local groups by raw SID. A second, lower-risk aspect: the substring match is not anchored to an ACE field boundary, so in principle the acronym could appear in an owner/group string rather than an ACE trustee field (practically unlikely in the canonical SDDL `inspect_file_sddl` emits).

Assessment: the string-match model is sound for the canonical SDDL forms the Windows API produces via `ConvertStringSecurityDescriptor`, but it is a deny-list of spellings, not a semantic trustee parse. A malicious or misconfigured ACL that spells Everyone by SID defeats it. Recommend (follow-up): parse trustee fields and compare resolved SIDs (`S-1-1-0`, `S-1-5-11`, `S-1-5-32-545`) rather than acronym substrings. This is the strongest finding of the review.

### F2.d — POTENTIAL-WEAKNESS (test-side) + QUESTION: the anti-fail-open guard tests were not fully updated for the new arm

Two guards exist:

1. **Runtime test** `key_custody_permission_check_fails_closed_when_unimplemented` (`src/lib.rs:2159-2174`, `#[cfg(not(unix))]`): expects `Err(PermissionValidationUnavailable)`. The commit narrowed the stub to `#[cfg(not(any(unix, windows)))]` but did not narrow this test's cfg. If the test compiles on Windows, it now exercises the *real* validators against a temp dir — which is not `D:P`-protected, so the arm returns `PermissionDenied`, and the `matches!(PermissionValidationUnavailable)` assertion fails. The test needs `#[cfg(not(any(unix, windows)))]`. Open question lowering severity: the test sits inside a module context that may itself be unix-gated (module attribute at `src/lib.rs:1938`); if so the mismatch is latent rather than an active Windows-test breakage. Either way the runtime guard no longer guards anything on Windows by design, and its cfg should be corrected.
2. **Source pin** `non_unix_key_custody_arm_does_not_return_ok` (`src/lib.rs:2318+`, runs on unix, scans the file text via `strip_non_code` at 2199-2316): pins the discard marker `let _ = (directory, file, policy);` (at `src/lib.rs:2332`) — which now matches only the narrowed stub, since the Windows arm discards only `policy` (`let _ = policy;`, `src/lib.rs:1907`, different text) — and asserts no `return Ok((` appears in the function prelude before the marker. This pin remains intact and still enforces that the non-unix/non-windows stub fails closed. However, it does not pin the Windows arm's validator calls: a regression that deleted `validate_windows_dpapi_root(directory)?` / `validate_windows_dpapi_file(file)?` from the arm would not trip any guard.

Verdict on (d): the guard is **not weakened in spirit** — the stub still fails closed and the source pin still enforces it — but the runtime guard's cfg is stale with respect to the new arm, and the Windows arm itself is unpinned. Recommend (follow-up): narrow the runtime test's cfg to `not(any(unix, windows))` and extend the source pin to require the two Windows validator calls.

---

## Summary table

| ID | Area | Class | One-line finding |
| --- | --- | --- | --- |
| F1.1 | sysinfo f454cbd8 | CONFIRMED-SAFE | Windows arm added; sole omission of its class; no other fn missing an arm (incl. resolved `ipc_socket_responsiveness_internal`, `src/lib.rs:6164-6212`). |
| F2.a | crypto 77262024 | CONFIRMED-SAFE (within model) | Windows arm cannot return `Ok` on a WD/AU/BU-exposed ACL; fails closed on symlink and SDDL read error. |
| F2.b | crypto 77262024 | POTENTIAL-WEAKNESS (moderate) | File check requires `D:` not `D:P`; no owner-SID assertion — narrow over-permissive ACLs accepted vs. unix owner-only bar. |
| F2.c | crypto 77262024 | POTENTIAL-WEAKNESS / QUESTION | Broad-SID rejection is acronym substring; raw-SID principals (e.g. `S-1-1-0` = Everyone) bypass it. Strongest finding. |
| F2.d | crypto 77262024 | POTENTIAL-WEAKNESS (test-side) | Runtime fail-closed test cfg stale for the new Windows arm; source pin intact but does not pin the Windows validator calls. |

**Bottom line:** both commits do what they claim and neither introduces a fail-open production path. Fix 1 is fully clean. Fix 2 is a genuine improvement over the previous always-unavailable stub and fails closed on its error paths, but its Windows ACL model is a deny-list of SDDL spellings rather than a semantic trustee check (F2.c), is asymmetric with the unix owner-only bar (F2.b), and its test-side guard needs a cfg follow-up (F2.d). All recommendations are follow-ups for the owning maintainers; this review changes no code.
