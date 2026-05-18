# Rustynet Security Posture Summary

A reviewer-facing snapshot of every fail-closed verifier, audit gate,
and security-tied invariant pinned in the workspace. Use this to
answer "what's hardened?" without reading every backlog tick.

Last refreshed: 2026-05-17.

## 1. Verifier modules + reviewed-floor coverage

Each module owns a typed evaluator, a collector (Linux/Windows-side
when needed), and a fail-closed report shape. The pinned test floor
catches silent test-suite shrinkage: if a refactor accidentally drops
named drift tests, the regression-coverage CI gate
(`scripts/ci/regression_coverage_gates.sh`) fails closed.

### Linux verifiers (7 modules, 196 pinned tests)

| Module                          | Floor | What it pins                                                                                             |
|---------------------------------|-------|----------------------------------------------------------------------------------------------------------|
| `linux_runtime_acls`            | 27    | `/etc/rustynet`, `/var/lib/rustynet`, `/run/rustynet`, `/var/log/rustynet` ownership + mode + reviewed roots; reviewed-roots-list snapshot; symlink-before-dir + symlink+mode first-fault precedence |
| `linux_service_hardening`       | 33    | systemd-unit hardening directives (`MemoryDenyWriteExecute`, `ProtectSystem`, `RestrictSUIDSGID`, etc.) + reviewed unit-file pin (`ExecStartPre` for killswitch-boot-check + `LoadCredentialEncrypted` lines) |
| `linux_dns_failclosed`          | 45    | resolv.conf loopback-only invariant; systemd-resolved stub-race detection; NetworkManager `[main] dns=` precedence drift; IPv6 / link-local / mapped / zone-id / bracketed-form rejection |
| `linux_mesh_status`             | 24    | Typed snapshot-load + freshness-boundary semantics (==max accepted, max+1 rejected); missing-peer aggregation; per-variant serde round-trip with `load_status` tag; forgiving-schema forward-compat |
| `linux_key_custody`             | 24    | WG-key + systemd-encrypted-credential-store custody (`/etc/rustynet/credentials/wg_key_passphrase.cred` 0600 root:root); legacy-plaintext-passphrase forbidden-at-rest; 8-entry canonical-list snapshot; per-variant serde + multi-entry drift aggregation |
| `linux_authenticode`            | 22    | Applicability invariant + reason text contract + schema_version pin + determinism + drift-mutation detection per field + canonical serialized snapshot |
| `linux_killswitch_boot`         | 21    | Boot-time invariant: tunnel-iface present ⇒ killswitch table must be programmed; `inet rustynet` table + `killswitch` + `forward` chains + reviewed rule fragments; off-Linux blocker |

### macOS verifiers (6 modules, 74 pinned tests)

| Module                          | Floor | What it pins                                                                                             |
|---------------------------------|-------|----------------------------------------------------------------------------------------------------------|
| `macos_runtime_acls`            | 16    | `/usr/local/var/rustynet` + `/usr/local/etc/rustynet` ownership + mode + reviewed roots; symlink + first-fault precedence parity with linux_runtime_acls |
| `macos_service_hardening`       | 15    | Reviewed launchd plist directives (`UserName`/`GroupName`/`RunAtLoad`/`KeepAlive`/`ProcessType`/`AbandonProcessGroup`); parser tolerance of dict/array values + inline XML comments |
| `macos_dns_failclosed`          | 16    | resolv.conf loopback-only invariant + IPv4/IPv6 link-local + IPv4-mapped IPv6 + 127.0.0.0/8 boundary + multi-directive search/domain parser + no-dedup drift aggregation |
| `macos_mesh_status`             | 9     | Default-state-path fallback + custom-path echo + per-variant serde on Ok / IntegrityMismatch / InvalidFormat (re-uses windows evaluator) |
| `macos_key_custody`             | 11    | WG-key custody contract parity with linux_key_custody; per-variant serde matrix complete (Missing / Invalid / Forbidden / AbsentAsExpected); overall_ok = {Ok | AbsentAsExpected} contract from both sides |
| `macos_authenticode`            | 7     | Applicability=false stub + reason-text content (Authenticode + Gatekeeper + launch-time mentions) + determinism + unknown-fields tolerance |

### Windows verifiers (8 modules, 278 pinned tests)

| Module                          | Floor | What it pins                                                                                             |
|---------------------------------|-------|----------------------------------------------------------------------------------------------------------|
| `windows_service_hardening`     | 33    | SDDL deny-list (WD/AU/BU principals), missing-SY/BA reject, unreviewed-owner reject, service-SID owner accept, interactive+LocalSystem reject |
| `windows_dns_failclosed`        | 67    | Loopback-only contract for interface DNS + NRPT rules (link-local / mapped / zone-id / bracketed-form reject); IPv6 NRPT sibling-coverage evaluator (union-semantics across rules); Router Advertisement suppression evaluator (RD-enabled + ra-sourced default-route fail-closed) |
| `windows_mesh_status`           | 23    | Reviewed-root path validation (`%TEMP%`/UNC reject), typed snapshot-load + age boundary (== accepted, +1 rejected) + expected-peers no-dedup + lan/exit-node fields don't gate verdict today |
| `windows_key_custody`           | 24    | DPAPI custody invariants + rotation tests (world-writable / unreviewed-owner / partial-rotation / temp-suffix / DACL widened to AU); per-variant serde round-trip Missing + Invalid + AbsentAsExpected + no-dedup-across-entries |
| `windows_authenticode`          | 38    | PE Certificate Table parse + WinVerifyTrust chain validation + reviewed thumbprint policy (allowlist + revocation denylist with denylist-takes-precedence) + Microsoft-cert-manager-format normalisation |
| `windows_registry_acls`         | 17    | Reviewed HKLM RustyNet service-key paths + forbidden DACL principals (WD/AU/BU/AN); cross-platform stub collector emits Unobserved entries (real Win32 collector follow-up) |
| `windows_paths`                 | 61    | SDDL grant/deny matcher (substring-match negative, exact ACE-type token); local-secret ACL evaluator forbidden-principal rejection; runtime-path validator UNC + user-temp reject + canonical ProgramData accept |
| `windows_ipc`                   | 15    | Named-pipe path validation against reviewed roots; SDDL security-policy generation per role (DaemonControl / PrivilegedHelper); client-authorization checks against the reviewed allowlist; length-prefixed privileged-request/response encode/decode with bounded MAX_WINDOWS_PRIVILEGED_MESSAGE_BYTES |

### Shared (platform-agnostic audit, 1 module, 45 pinned tests)

| Module                          | Floor | What it pins                                                                                             |
|---------------------------------|-------|----------------------------------------------------------------------------------------------------------|
| `secret_log_audit`              | 45    | Forbidden placeholder tokens in log macros (passphrase_bytes / private_key_bytes / signing_key_bytes / wrapped_secret / decrypted_secret / plaintext_key / raw_passphrase / secret_bytes / signing_seed); Debug + Display + ToString deny on canonical secret-bearing types; hex + base64 encode wrappers around forbidden idents; secret-material equality (==/!=) without ct_eq with structured allowlist + per-entry justification; deprecated-crypto-imports (`use sha1` / `use md5` / `use md_5` / `use des` / `use des3` / `use triple_des`) with boundary-terminator check that rejects safe-name lookalikes (sha2 / sha3 / descriptor / md_hashlib) |

### Aggregate

- **22 verifier + audit modules** across 4 groups, **593 pinned tests** on the regression-coverage gate floor (sum of per-module floors: linux 196 + macos 74 + windows 278 + shared 45).
- Every Linux verifier has a macOS + Windows analog (or equivalent surface). Every Windows verifier has a Linux analog (or equivalent surface in `linux_runtime_acls` / `windows_paths`).
- Workspace test sweep: **2786 tests, 0 failing** (rustynetd + rustynet-cli + control + relay + policy + backends, measured 2026-05-18 post X4/X7 expansion).

## 2. CLI exit-code taxonomy (X6)

Reviewed contract in `rustynetd::exit_codes::ExitCode`:

| Code | Variant            | Meaning                                                  |
|------|--------------------|----------------------------------------------------------|
| 0    | `Success`          | command did what was asked                               |
| 1    | `GenericFailure`   | last-resort fallback                                     |
| 64   | `BadArgs`          | invalid argv / missing required flag / unknown sub       |
| 65   | `ConfigError`      | on-disk config failed validation                         |
| 70   | `TransientFailure` | IO / network / retry-safe                                |
| 78   | `PolicyReject`     | fail-closed gate refused the operation                   |

Aligned with BSD `sysexits.h` (`EX_USAGE`/`EX_DATAERR`/`EX_SOFTWARE`/`EX_CONFIG`) so existing CI wrappers and `systemd RestartPreventExitStatus=` lists work without Rustynet-specific knowledge.

**Coverage**: 100% of bin/*.rs binaries under `crates/rustynet-cli/src/bin/` (70 binaries) classify their failure shapes through the taxonomy. Security-critical verdicts (signature verification, attestation, drift, tampering, leak detection, perf regression, platform-mismatch) uniformly map to `PolicyReject(78)` so retry-only-on-70 CI loops never accidentally retry a fail-closed verdict.

Runbook: [`CliExitCodeTaxonomy.md`](./CliExitCodeTaxonomy.md).

## 3. Static no-secret-leakage audit (X3)

`crates/rustynetd/src/secret_log_audit.rs` is a `cargo test`-time static source-walk audit. Sweeps every `.rs` file under reviewed source roots per scanner — `crates/rustynetd/src/` + `crates/rustynet-cli/src/` for the placeholder / Debug / hex / base64 / Display scanners (the daemon's own log surface), `crates/rustynet-relay/src/` + `crates/rustynet-control/src/` for the secret-material-equality scanner (control-plane + relay surfaces that handle session tokens / nonces / MACs), and `crates/` workspace-wide for the deprecated-crypto-imports scanner — and fails closed when any of these patterns appears:

1. **Forbidden placeholder tokens in log/print/format macros** — `{passphrase_bytes}`, `{private_key_bytes}`, `{signing_key_bytes}`, `{wrapped_secret}`, `{decrypted_secret}`, `{plaintext_key}`, `{raw_passphrase}`, `{secret_bytes}`, `{signing_seed}`. Matches `{token}`, `{token:?}`, `{token:x?}` shapes; ignores commented-out lines and path-only logs.

2. **Forbidden `Debug` derive / impl on secret-bearing types** — `PassphraseMaterial`, `WrappedKeyMaterial`, `RuntimePrivateKey`, `SigningKeyMaterial`. No-`Debug` is the structural guarantee that `{:?}` cannot leak inner bytes.

3. **Forbidden hex-encoder shapes** — `hex::encode(forbidden_ident)`, `format!("{:02x}…", forbidden_ident[..])` inside log macros.

4. **Forbidden base64-encoder shapes** — `base64::*encode(forbidden_ident)`, `STANDARD.encode(forbidden_ident)` (covers legacy + fully-qualified forms).

5. **Forbidden `Display` / `ToString` impl on canonical secret-bearing types** — same list as the Debug ban.

6. **Secret-material equality compares (`==` / `!=`) without `ct_eq`** — flags raw equality on forbidden tokens (token / csrf / session_key / nonce / mac / hmac / session_id / signature). Suppressed by `ct_eq` on the same line OR a structured `(path, line, justification)` entry in `REVIEWED_SECRET_EQUALITY_EXCEPTIONS`.

7. **Deprecated-crypto-imports** — rejects `use sha1` / `use md5` / `use md_5` / `use des` / `use des3` / `use triple_des` (with boundary-terminator check to reject safe-name lookalikes like `sha2` / `sha3` / `descriptor` / `md_hashlib`).

Workspace sweeps run on every `cargo test` invocation. Current tree: **0 offenders** across all 7 scanners. Allowlist scope is narrow (only the audit module itself, which necessarily mentions the forbidden tokens / forbidden crate names as constants).

## 4. Boot-time + ordering invariants

| Invariant                                        | Where it lives                                      |
|--------------------------------------------------|-----------------------------------------------------|
| `ExecStartPre=linux-killswitch-boot-check`        | `scripts/systemd/rustynetd.service` — refuses to start daemon when iface-up + table-missing |
| `LoadCredentialEncrypted=wg_key_passphrase`       | Same unit; pinned by `reviewed_unit_file_pins_credential_load_lines` test |
| `MemoryDenyWriteExecute=true`                     | Same unit; pinned by `reviewed_unit_file_pins_memory_deny_write_execute` test |
| reviewed-root path validation on Windows mesh state | `WindowsMeshStatusReport` rejects `%TEMP%` / UNC paths before any filesystem read |
| systemd-resolved socket-race detection            | `LinuxDnsFailclosedSnapshot.systemd_resolved_stub_present` + evaluator |
| NetworkManager `dns=default` precedence drift     | `LinuxDnsFailclosedSnapshot.network_manager_dns_mode` + evaluator |
| Authenticode thumbprint allowlist + denylist     | `WindowsAuthenticodeThumbprintPolicy` — denylist takes precedence (rotation safety) |

## 5. Phase A typed-schema migration (X2)

`serde_json::Value` walks in `ops_*.rs` modules being replaced by typed serde views with `#[serde(flatten)] extra: Map<String, Value>` for forward-compat. Each typed view exposes `into_value_map()` so downstream Map-walking helpers keep working unchanged.

Modules with typed views landed:
- `ops_phase9.rs` — 4 views (`Phase9DrDrillView`, `Phase9IncidentDrillView`, `Phase9SloWindowView`, `Phase9PerformanceSampleView`); all 4 NDJSON consumers migrated
- `ops_network_discovery.rs` — `NetworkDiscoveryBundleView`
- `ops_fresh_install_os_matrix.rs` — `FreshInstallOsMatrixReportView`
- `ops_cross_network_reports.rs` — 3 views (`CrossNetworkSoakMonitorSummaryView`, `CrossNetworkReportPayloadView`, `CrossNetworkSshTrustSummaryView` + `CrossNetworkSshTrustTargetView` substruct)
- `ops_live_lab_failure_digest.rs` — 4 views (full module migration, 5/5 walks eliminated)
- `ops_live_lab_orchestrator.rs` — writer side fully migrated. Typed views (in landing order): `LiveLabOrchestratorNoLeakReportView`, `RunSummaryNodeView`/`RunSummaryWorkerView`/`RunSummaryStageView`/`LiveLabRunSummaryView`, `CrossNetworkForensicsManifestView`/`NodeReportView`/`BundleValidationView`, plus the 2026-05-18 batch: `LiveLinuxServerIpBypassReportView` (+ Checks/Evidence), `LiveLinuxControlSurfaceReportView` (+ 5 nested views), `LiveLinuxEndpointHijackReportView` (+ Checks/Evidence), `RealWireguardExitnodeE2eReportView` (+ Checks), `RealWireguardNoLeakUnderLoadReportView` (+ Checks/Metrics), `ActiveNetworkSignedStateTamperReportView` (+ Checks/Hosts/Evidence), `ActiveNetworkRoguePathHijackReportView` (+ Checks/Hosts/Evidence), `E2eDnsQueryResultView`. Only `execute_ops_read_json_field` retains a `Value` walk — intentional shape-agnostic JSON-pointer reader.

**Pattern**: every required-string + required-u64 field becomes a typed field with serde required-field semantics. A missing or wrong-type value now fails at parse time with a precise per-line error including the file label, instead of surfacing later as an `ok_or_else` on a stale `Value::as_str()` result.

## 6. CI gates

| Gate                                              | What it runs                                                                 |
|---------------------------------------------------|------------------------------------------------------------------------------|
| `cargo fmt --all -- --check`                       | format consistency                                                           |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | lint cleanliness with warnings-as-errors                  |
| `cargo test --workspace --all-targets --all-features` | full workspace test sweep (2786 tests as of 2026-05-18)                   |
| `cargo audit --deny warnings`                      | dependency CVE / advisory scan                                               |
| `cargo deny check bans licenses sources advisories` | dependency policy gate                                                      |
| `scripts/ci/regression_coverage_gates.sh`          | per-module test-count floor (22 modules across 4 groups, 593 pinned tests)   |
| `scripts/ci/start_modularization_smoke.sh`         | bash module / dispatcher contract (32 checks)                                |
| `scripts/ci/secrets_hygiene_gates.sh`              | structured secret-leak audit + required tests                                |
| Per-phase gate scripts (`phase1_gates.sh` … `phase10_gates.sh`) | per-phase release-readiness pins                                |

## 7. Operating-policy hygiene

Verified clean as of this refresh:
- **Zero TODO / FIXME / XXX / HACK markers** in production code paths across all 8 crates (per CLAUDE.md "Do not defer in-scope requirements behind TODO/FIXME").
- **85 `#[allow(dead_code)]` markers**, all carrying justification comments (test-exposed parsers, enum variants used in tests, typed-view fields exercised via round-trip tests).
- **Zero `unsafe` code** outside the `rustynet-windows-native` crate (enforced by `check_no_unsafe_code.rs` gate → `PolicyReject` on violation).

## 8. Known open items (not blocking)

Per `PlatformImprovementBacklog_2026-05-14.md`:

- **L6 / L7 / L8 lab-side validation** — cross-boot passphrase stability, IPv6 NAT sibling table, netns reboot integration test. Need Linux lab fixtures.
- **W1 / W4-collector / W5-collector / W7** — PowerShell helper JSON emit (sync-source / install-release / restart-runtime / verify-runtime / collect-diagnostics sub-phases), Win32 `RegGetKeySecurity` collector, Win32 `CryptQueryObject` thumbprint extraction, Windows install-release real runtime. Need Windows-native infra.
- **L2 nftables IPv6 parity + named-chain integrity** — runtime-ACL `inet rustynet` / `ip rustynet` family wiring inspection. Verifier extension lives in `phase10.rs`; no test floor yet because the surface is outside the per-platform `linux_runtime_acls` module.
- **X2 remaining** — writer-side fully migrated on `ops_live_lab_orchestrator.rs` (only `execute_ops_read_json_field` retains a `Value` walk, intentional shape-agnostic JSON-pointer reader by design). `ops_cross_network_reports.rs` has 5 helper `Value` walks intentionally kept (path-evidence extractors over `&[Value]` / `Option<&Value>`) and nested `path_evidence` block walkers as a future slice.

Each is incrementally landable when the relevant infra (lab / Windows host / Win32 bindings) is available.
