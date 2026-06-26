# Cross-Platform CI Health — pre-existing breakage cleanup + runbook — 2026-06-25

Status: **WINDOWS JOB FULLY GREEN as of `e3f99ce` (2026-06-25)** — `Build + test
Windows-portable crates` AND `Security gates` both pass on `windows-2022` for the
first time. All code-caused red is resolved (relay + rustynetd test-portability,
the secret-equality line-drift + drift-resistant re-anchor, the macOS budget-test
determinism, and the advisory-db CRLF parse fix). The only remaining red is the
documented-environmental class: macOS = the single `vm_lab` Gatekeeper/`trustd`
subprocess flake (§4.1, user-deferred; verified on `e3f99ce`: 1751 passed, 1
failed — the budget-test fix landed, only the flake remains); Debian + Linux-E2E
= `cargo: not found` bootstrap (§4.2, deferred infra). Author: Iwan-Teague.

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

**Host caveat (the macOS lab laptop):** this runbook is **Linux-only**. On the
`aarch64-apple-darwin` lab host the pinned `1.88.0` toolchain cannot resolve the
windows `rust-std` even after `rustup target add` / `component add` (every
windows-target `cargo check`/clippy — via rustup `1.88.0` too — aborts with
`can't find crate for core` at `cfg-if`/`subtle`/`cpufeatures`). Both
`x86_64-pc-windows-gnu` and `-msvc` fail identically, so there is **no working
local Windows cross-check on this laptop** — Windows-targeting changes here must
be reasoned through `cfg`-by-`cfg` and verified by the actual Windows CI job. Run
the cross-clippy from the Linux dev box instead.

**TOOLCHAIN TRAP on the macOS lab laptop (READ THIS before trusting any local
gate result here).** `cargo`/`rustc` on `PATH` is **Homebrew's `1.94.1`**
(`/opt/homebrew/bin/cargo`), NOT rustup — so `rust-toolchain.toml`'s pin to
`1.88.0` is **silently ignored** and `cargo +1.88.0 …` fails (`no such command:
+1.88.0`, because Homebrew cargo is not a rustup shim). The CI runs `1.88.0`, and
`1.94.1`'s clippy is **stricter** (e.g. it raises a `collapsible_if` let-chain
lint on `linux_exit_dns_failclosed.rs` that `1.88.0` does not), so the Homebrew
toolchain produces **false-positive** clippy failures that do not reflect CI. To
gate against the CI toolchain on this host, prepend the rustup `1.88.0` bin dir:
```
export PATH="$HOME/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin:$PATH"
cargo clippy --version   # must print clippy 0.1.88, not 0.1.94
```
(`rustup run 1.88.0 cargo clippy` is NOT enough — the `cargo clippy` subcommand
still resolves `cargo-clippy` off `PATH` to the Homebrew driver; prepend the
toolchain bin dir as above.)

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

## 3b. Second Windows red: relay Windows-portable tests (`7734156`)

Once the persist fix (§3) let the Windows build compile *and pass*
`rustynet-control`, the next red surfaced in `rustynet-relay`: **21 tests failed**
on `windows-2022` (run `28179119351`). Same shape as §3 — the tests had only ever
run on Linux/macOS until the cfg-gating made the crate compile on Windows, so they
were written Unix-only and now hit the Windows-specific filesystem/ACL/path-root
gates that are no-ops on Unix:

- config + `parse_args_from` tests passed `/tmp/...` paths, not
  `Path::is_absolute()` on Windows ⇒ `RelayConfig::validate()` returned the
  absolute-path error before the assertion's target check;
- env-file parse tests drove the full `load_windows_relay_service_args`, which on
  Windows additionally enforces the reviewed-root path gate + SDDL ACL inspection
  that a transient temp file cannot satisfy;
- runtime-arg tests validated against non-existent `C:\...` files, so the Windows
  `symlink_metadata` + `inspect_file_sddl` step failed on input the Unix no-op ACL
  accepted.

Fix (`7734156`): **no production gate weakened** — the hardened paths still call
the same gates in the same order. The tests were made cross-platform by separating
pure validation logic from filesystem/ACL I/O: extract
`parse_windows_relay_service_args_from_text` (env-file grammar + JSON shape) and
`enforce_windows_relay_env_file_size` (DoS cap) out of the loader; split
`validate_windows_relay_service_runtime_path` into a pure `_path_policy` gate +
the existing ACL gate; point grammar/size/shape/policy tests at the pure
functions; use platform-absolute / reviewed-root paths in the config + entry
tests; and keep one `#[cfg(not(windows))]` end-to-end test each for the env-file
loader + full runtime-arg validator so the Unix I/O branch stays covered and the
symbols stay live on Unix. SDDL ACL evaluation remains covered cross-platform by
`relay_windows_service_runtime_acl_requires_hardened_file_and_parent`.

Host gates green (fmt + clippy `-D warnings` + `cargo test -p rustynet-relay`:
82+56 tests pass). **CI-CONFIRMED** on run `28187451302` (`7734156`): the Windows
job's build+test step now passes every relay test (`21 passed`, `20 passed`, …) —
the relay layer is green. Fixing it peeled the `cargo test` fail-fast back to the
next failing crate, `rustynetd` (§3c).

---

## 3c. Third Windows red: rustynetd Windows-portable tests (`<next-commit>`)

With the relay layer green, the Windows `cargo test` reached `rustynetd` and
surfaced the next set of Unix-only-test failures (run `28187451302`). These were
NOT new — `cargo test` is **fail-fast across binaries** by default, so the prior
runs stopped at the first failing crate and never ran `rustynetd`'s tests at all
(the prior Windows + macOS + Debian jobs all bailed earlier, which is also why
none of these had ever been seen). Categories:

- **H2 gossip transport is unix-only** (`gossip_transport.rs` returns
  `Unsupported` on `cfg(not(unix))`, Track Beta). Tests that `.bind().expect()`
  it panic on Windows. Gated `#[cfg(unix)]`: 5 `gossip_runtime` tests + the
  `loopback_bind` helper; 1 `enrollment_consume` test + its `loopback_bind`; and
  — found by the parallel audit (§below) — **2 whole integration-test crates**
  (`tests/enrollment_two_peer_redeem.rs` 5 tests, `tests/gossip_three_peer_mesh.rs`
  6 tests) via a crate-root `#![cfg(unix)]` (gates the tests AND their `Peer`
  harness + helpers in one stroke, so no unused-code `-D warnings`).
- **H3 linux-only DNS module** — `linux_dns_protect` selector-validation test
  asserted `.contains("unsupported")`, but the `cfg(not(unix))` path returns
  "only supported on Linux"; gated the test `#[cfg(unix)]`.
- **H4 path-separator in a string allowlist** — `secret_log_audit`
  `equality_hit_is_allowlisted` did `file_path_label.ends_with("crates/…/x.rs")`,
  but on Windows the swept label mixes `/` (sweep-root literal) with `\` (dir
  walk); normalized `\`→`/` before the suffix match. **Security-preserving** (the
  reviewed exceptions just apply identically cross-OS; non-allowlisted secret
  equality still fails everywhere).
- **H4b stale line-number allowlist (also fails Linux/macOS, was masked)** —
  the same `secret_log_audit` workspace sweep reported 11 control/lib.rs sites
  as offenders because commit `4c3d513` (the §3 persist fix) inserted 6
  `#[cfg(unix)]` lines into `control/src/lib.rs` and did **not** re-sync the
  `REVIEWED_SECRET_EQUALITY_EXCEPTIONS` line numbers (a known-fragile,
  line-numbered allowlist — git shows prior re-syncs `ccf0b4a`, `a4c0ddb`). Every
  reviewed site drifted +6 (1488→1494, …). Re-synced all 11 (each verified still
  a benign `nonce==0` / all-zero-sentinel / structural check, not a secret
  compare). This had been invisible because Linux CI never runs (bootstrap fails)
  and macOS CI fail-fast stopped at an earlier flake before this test. **Follow-up
  filed:** make the allowlist drift-resistant (anchor on line CONTENT, not number).
- **H5 platform error wording** — `windows_registry_acls` stub test asserted the
  drift reason contained `"missing required"` / `"invalid required"`, but the real
  Windows collector emits `"required registry key missing"` / `"registry ACL
  invalid"` (the CI runner has no RustyNet services, so the real collector reports
  `Missing`); corrected the assertion substrings to the wording the evaluator
  actually emits.

Plus a CI improvement: added **`--no-fail-fast`** to the Windows job's `cargo
test` so one run surfaces the COMPLETE Windows failure set instead of one crate
at a time (each masked failure otherwise costs a full ~12-min round-trip, since
the Windows tests cannot be run locally on this host).

**Parallel completeness audit.** Because fail-fast hides downstream failures and
no local Windows test run exists, a fan-out audit (one agent per Windows-CI
package + adversarial per-finding verify) swept all 10 packages for the H1–H7
hazard taxonomy. It confirmed exactly the 11 integration-test H2 hazards above
(and rejected 5 false positives), and found no hazards in the other 8 packages —
giving confidence the fix set is complete modulo what `--no-fail-fast` will
reveal. Host gates green on the **rustup `1.88.0`** toolchain (§1 trap): fmt +
clippy `-D warnings` + `cargo test -p rustynetd --all-targets` = 1789 lib + all
integration/bin tests pass, `no_secret_material_equality_in_workspace` ok.

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

3. **Two REVIEW items from the `f5b38be` cfg-gating cleanup** — **REVIEWED
   2026-06-25: both removals CONFIRMED SAFE, no security gap, no action needed.**
   - `daemon::validate_parent_directory_security` (`cfg(windows)`) — removed; had
     no caller. **Verdict: safe.** Windows parent-directory hardening is provided
     by a *stronger* boot-time authoritative gate, not a per-file parent check:
     `validate_windows_runtime_startup_acls()` is wired into daemon startup
     (`daemon.rs:9252`, immediately after `validate_daemon_config`, logging
     "configuration and runtime ACLs validated") and **fails the daemon closed
     (`DaemonError::InvalidConfig`)** if ANY of the 9 reviewed root directories
     (`state/config/log/trust/membership/keys/secret/key-custody/credentials`,
     `WINDOWS_RUNTIME_STARTUP_ACL_ROOTS`) is missing, a symlink, or has a
     non-hardened ACL. Combined with reviewed-root containment (sensitive files
     must live under those roots — `under_reviewed_root`), per-file ACL checks
     (`validate_windows_runtime_acl` / `validate_windows_local_secret_acl`), and
     NTFS ACL inheritance, every sensitive file's parent chain is protected. The
     removed stub was dead code whose function is fully subsumed — re-wiring a
     redundant per-file parent check would add nothing.
   - `privileged_helper::validate_privileged_program_binary` (`cfg(windows)`) —
     removed; orphaned once binary resolution + exec became unix-only. **Verdict:
     safe.** The privileged-helper exec model is unix-only; on Windows there is
     no privileged-helper binary to resolve/exec, so validating one is moot.

4. **macOS "Workspace validation" clippy — code-caused, FIXED 2026-06-27.**
   The macOS red was previously attributed to the `vm_lab` Gatekeeper flake
   (§4.1). That was wrong: Workspace-validation runs `cargo fmt` + `cargo
   clippy --workspace --all-targets --all-features --locked -- -D warnings`
   (compile-only), so a subprocess-spawn *test* flake cannot fail it. The real
   blocker was clippy `-D warnings` errors that cargo's per-crate fail ordering
   surfaced one crate at a time (CI showed only the first). Three crates were
   red, all introduced by the recent MCP + macOS/Windows-traffic work:
   - `rustynet-mcp`: deepseek.rs doc-list overindentation (×9) + the 8-arg
     `ship_crates` cache-seeding helper (`too_many_arguments`, justified
     targeted allow — host-side dev tooling, not a production path).
   - `rustynetd`: `assert!(MACOS_ANCHOR_POLL_ATTEMPTS …)` on a constant
     (`assertions_on_constants`). Replaced the runtime test with a
     compile-time `const _: () = assert!(…)` at the constant — strictly
     stronger (build-time, platform-independent).
   - `rustynet-cli`: macos_traffic.rs doc-list-without-indentation (×5, fixed
     with blank `///` separators + col-0 list items) + a windows_traffic.rs
     uninlined `format!` arg.
   Verified: full-workspace `cargo clippy … -D warnings` green + `cargo fmt`
   clean on the rustup `1.88.0` (CI) toolchain. The `vm_lab` Gatekeeper flake
   (§4.1) is a separate *test-run* concern and remains deferred.

5. **Windows "Security gates" step** (`cargo audit` + `cargo deny`) has been
   *skipped* in every run so far because the build/test step failed first. Once
   the Windows job goes green it will run for the first time.
   **Pre-empted 2026-06-25 on the lab host: the dependency surface is CLEAN.**
   `cargo audit --deny warnings` scanned 210 crate deps with no vulnerabilities;
   `cargo deny check bans licenses sources advisories` reported `advisories ok,
   bans ok, licenses ok, sources ok`.
   **BUT the first real Windows run (3d68930) surfaced an environmental
   advisory-db PARSE failure, not a real finding:** `failed to load advisory:
   failed to parse advisory from '…\advisory-db\crates\abi_stable\RUSTSEC-2020-0105.md':
   failed to find toml block` (`abi_stable` is not even a workspace dep). Cause:
   git-for-Windows defaults to `core.autocrlf=true`, so cargo-audit's freshly
   cloned RustSec advisory `.md` files get CRLF line endings and the TOML-block
   parser chokes. Fixed by pinning `git config --global core.autocrlf false`
   ahead of the Windows Security-gates `cargo audit` / `cargo deny` calls so the
   advisory-db parses identically to Linux/macOS. (Push-and-see: cannot be
   reproduced on the macOS lab host.)

---

## 5. CI state snapshot

| Job | State | Blocker |
|---|---|---|
| Windows build+security | ✅ **GREEN @ `e3f99ce`** — build+test + Security gates both pass | none |
| macOS build+security | clippy GREEN @ 2026-06-27 (§4.4); test-run TBD | Workspace-validation clippy red was **code-caused** (3 crates), NOT the `vm_lab` flake — fixed 2026-06-27 (§4.4). Remaining macOS concerns are in the *test-run* step (after clippy): the `vm_lab` Gatekeeper flake (§4.1) + a `userspace_shared_macos` socket-poll-budget timing test seen on `7734156` — both surface only once clippy is green, which it now is. |
| Debian 13 build+security | red | `cargo: not found` bootstrap (§4.2, deferred) |
| Linux real WireGuard E2E | red | `cargo: not found` bootstrap (§4.2, deferred) |

> Note: the `secret_log_audit` line-drift (§3c, H4b) and these rustynetd
> portability tests would also fail the macOS + Debian jobs once they get past
> their own earlier blockers — the fixes in §3c are cross-OS, not Windows-only.

Verified 2026-06-25 against run `28179119351` (the `3f466ec` push, before the
relay fix): Debian + Linux-E2E failed identically at "Bootstrap CI tools"
(`cargo: not found`), confirming §4.2 is pre-existing/infra and unchanged by the
relay fix; macOS failed on the single `vm_lab` timeout-transition flake (§4.1);
Windows failed only on the 21 relay tests now fixed in §3b.

---

## 6. Cross-references
- `LiveLabCoverageAndHonestyAudit_2026-06-25.md` §8 (progress log + the TODO list
  this doc expands)
- `LinuxBlindExitDataplane_2026-06-25.md` (the blind_exit fix landed this pass +
  the broken `spawn_privileged_capture_helper` socket-test-helper finding)
- `CrossPlatformRoleParityPlan_2026-06-21.md` (the release-blocking parity mandate)
