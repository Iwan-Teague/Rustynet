# Cross-Platform CI Health — pre-existing breakage cleanup + runbook — 2026-06-25

Status: **IN EXECUTION**. Windows clippy + a real Windows persist bug cleared;
macOS / Debian / Linux-E2E jobs still red on pre-existing/infra issues (tracked
below). Author: Iwan-Teague.

Purpose: the `cross-platform-ci.yml` workflow (jobs: **Windows build+security**,
**macOS build+security**, **Debian 13 build+security**, **Linux real WireGuard
E2E**) had been red since an older commit, which blocked *all* trustworthy
cross-OS verification. This doc records what was actually broken, the method used
to fix the Windows breakage **without CI round-trips**, and the remaining TODOs.

---

## 1. The windows-gnu cross-clippy runbook (reuse this)

The Windows CI lints are reproducible **locally on Linux** by cross-compiling to
the `x86_64-pc-windows-gnu` target. clippy lints are target-family-agnostic, so
a gnu cross-clippy that is green ⇒ the MSVC clippy step is green too. This turned
a ~10-min-per-iteration CI loop into a local one.

Setup (once):
```
rustup target add x86_64-pc-windows-gnu
# mingw linker (Debian/Ubuntu): apt-get install -y gcc-mingw-w64-x86-64
```

Run (the exact 10 packages the Windows CI job builds):
```
CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
  cargo clippy --target x86_64-pc-windows-gnu \
  -p rustynetd -p rustynet-windows-native -p rustynet-crypto -p rustynet-policy \
  -p rustynet-dns-zone -p rustynet-control -p rustynet-backend-api \
  -p rustynet-backend-stub -p rustynet-relay -p rustynet-local-security \
  --all-targets --all-features --locked -- -D warnings
```

**Limitation:** this catches *compile/lint* failures only. It does **not** catch
Windows *runtime* test failures — running the gnu test binaries needs wine, which
is not configured here. The trust-state persist bug (§3) was a runtime failure
and was only visible once the Windows CI build compiled far enough to run tests;
it was diagnosed by reading the code, not by local execution. When a fix targets
Windows runtime behavior, the gnu cross-clippy proves it compiles; the CI run is
still the authority for "the test passes".

---

## 2. What was cleared (commits, all author Iwan-Teague, no AI trailers)

| Commit | Scope |
|---|---|
| `ac394ba` | initial pre-existing macOS + Windows cross-platform-ci breakage |
| `7bed606` | Windows crypto unused-var + macOS run-provenance test diagnosis |
| `2d36e98` | Windows clippy breakage in local-security + backend-wireguard |
| `0b7205b` | gate now-unused `std::fs` import in local-security on unix |
| `f5b38be` | **the big one** — ~79 cfg-gating clippy errors across `rustynetd` (`privileged_helper`, `daemon`, `key_material`, `gossip_transport`, `dataplane_candidates`), `rustynet-control`, `rustynet-relay`, `rustynet-crypto` |
| `4c3d513` | **real Windows bug** — trust-state parent-dir fsync gated to unix (§3) |

The `f5b38be` cleanup gated unix-only helpers/constants/structs/imports and the
privileged-helper wire-protocol machinery with the `cfg` matching their users
(mostly `cfg(unix)`) — no functioning code deleted, no `-D warnings` weakened,
no blanket `allow`s. Verified: windows-gnu cross-clippy **0 errors**, native
Linux clippy **0**, `cargo fmt` clean, Linux test failure set byte-identical to
the pre-change baseline.

---

## 3. Real Windows bug fixed: trust-state persist (`4c3d513`)

Once `f5b38be` let the Windows build compile far enough to run tests,
`rustynet-control` failed 2 tests on `windows-2022`
(`trust_state_persist_and_integrity_check`,
`scale::trust_hardening_fails_closed_when_state_missing_or_mismatched`), both
`PersistFailure`.

Root cause: `atomic_write_secure` (crates/rustynet-control/src/lib.rs) opened the
**parent directory as a file** and `sync_all()`'d it after the atomic rename.
That directory fsync works on unix but fails on Windows (`File::open` on a
directory needs `FILE_FLAG_BACKUP_SEMANTICS`, which it does not request). So
`persist_trust_state` returned `PersistFailure` on Windows — a real fail-closed
regression for a security-critical path (a Windows daemon could not persist
signed trust state).

Fix: gate the directory fsync to `cfg(unix)` (durability is provided by the
atomic rename), mirroring the identical fix in
`rustynet-crypto::write_atomic_encrypted_key_file`. Linux unchanged (310 tests
pass); windows-gnu cross-clippy 0; CI confirmation pending.

---

## 4. Remaining CI TODOs

1. **macOS flaky `vm_lab` subprocess tests** (job: macOS build+security,
   "Workspace validation"). Gatekeeper/`trustd` first-run signing latency makes
   a couple of `vm_lab` subprocess-spawn tests intermittently fail on `macos-14`
   (they pass on Linux). This is a macOS-CI test-environment flake, not a code
   bug — needs a warm-up / bounded-retry / skip-on-CI gate. **User decision
   2026-06-25: leave it for now.**

2. **Debian 13 + Linux real-WireGuard-E2E** both fail at "Bootstrap CI tools"
   with `cargo: not found` — the runner/container PATH does not expose cargo.
   Pre-existing infra defect, independent of source. **User decision: deferred.**

3. **Two REVIEW items from the `f5b38be` cfg-gating cleanup** (behavior-preserving
   dead-stub removals; flag before treating as final):
   - `daemon::validate_parent_directory_security` (`cfg(windows)`) — removed; had
     no caller (Windows `validate_file_security` validates path + ACL inline). If
     Windows parent-directory ACL hardening is wanted, wire an equivalent
     `validate_windows_runtime_acl(parent, ...)` + non-symlink-dir check into the
     Windows `validate_file_security` as a deliberate, tested change.
   - `privileged_helper::validate_privileged_program_binary` (`cfg(windows)`) —
     removed; orphaned once binary resolution + exec became unix-only.

4. **Windows "Security gates" step** (`cargo audit` + `cargo deny`) has been
   *skipped* in every run so far because the build/test step failed first. Once
   the Windows job goes green it will run for the first time and could surface
   pre-existing supply-chain advisories/bans. cargo-audit/cargo-deny are not
   installed in this dev sandbox, so this could not be pre-empted locally —
   watch the first green-build run.

---

## 5. CI state snapshot

| Job | State @ `4c3d513` | Blocker |
|---|---|---|
| Windows build+security | clippy cleared; persist fix pushed | awaiting CI confirm of persist fix; then Security gates run for the first time (§4.4) |
| macOS build+security | red | flaky `vm_lab` subprocess tests (§4.1, left) |
| Debian 13 build+security | red | `cargo: not found` bootstrap (§4.2, deferred) |
| Linux real WireGuard E2E | red | `cargo: not found` bootstrap (§4.2, deferred) |

---

## 6. Cross-references
- `LiveLabCoverageAndHonestyAudit_2026-06-25.md` §8 (progress log + the TODO list
  this doc expands)
- `LinuxBlindExitDataplane_2026-06-25.md` (the blind_exit fix landed this pass +
  the broken `spawn_privileged_capture_helper` socket-test-helper finding)
- `CrossPlatformRoleParityPlan_2026-06-21.md` (the release-blocking parity mandate)
