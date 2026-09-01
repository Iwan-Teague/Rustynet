# Live-Lab Cross-Platform Custody, Secrets-in-Logs, and Runtime-ACL Stage Design

**Date:** 2026-09-01
**Status:** DESIGN ONLY — no code changed in this document's preparation. Implementation is owner-gated: it must not begin until (a) a separate adversarial review of this design has been completed and (b) the live lab is available for proving. All live-proving evidence in this document is explicitly marked as pending lab availability; no stage described below has been live-proven on macOS or Windows.
**Scope:** GAP-6 — native key-custody validation, secrets-not-in-logs validation, and runtime-ACL validation for macOS and Windows in the live-lab stage suite. This document is the design artifact for closing the gap; it is not an implementation record.
**Tracking mandate:** `CrossPlatformRoleParityPlan_2026-06-21.md` (release-blocking parity mandate) and `CrossPlatformRoleParityRefresh_2026-07-23.md` (per-role × per-OS status on the Rust `--node` engine of record).

---

## 1. Grounding verdict against the real code

**Verdict: PARTIAL.** The claim that cross-platform key-custody, secrets-in-logs, and runtime-ACL validation is "Linux-only today" is **confirmed at the adversarial/live-stage layer** and **refuted at the posture (self-check) validator layer**. Both halves are stated precisely below, each with file:line evidence read directly from the working tree on 2026-09-01.

### 1.1 What already exists on macOS and Windows (refutes the unconditional "Linux-only" claim)

Per-platform **posture validators** — daemon self-check commands invoked per-node by the Rust `--node` orchestrator — exist and are wired end-to-end for key custody and runtime ACLs:

| Component | Linux | macOS | Windows |
|---|---|---|---|
| Custody validator dispatch | `validate_linux_key_custody` | `validate_macos_key_custody` | `validate_windows_key_custody` |
| Runtime-ACL validator dispatch | `validate_linux_runtime_acls` | `validate_macos_runtime_acls` | `validate_windows_runtime_acls` |
| Daemon subcommand | `rustynetd linux-key-custody-check` / `linux-runtime-acls-check` | `rustynetd macos-key-custody-check` / `macos-runtime-acls-check` | `rustynetd windows-key-custody-check` / `windows-runtime-acls-check` |
| Report evaluator | `evaluate_linux_key_custody_report` / `evaluate_linux_runtime_acls_report` | `evaluate_macos_key_custody_report` / `evaluate_macos_runtime_acls_report` | `evaluate_windows_key_custody_report` / `evaluate_windows_runtime_acls_report` |

Evidence:

- `crates/rustynet-cli/src/vm_lab/role_validation/key_custody.rs:42–70` — `validate_macos_key_custody` dispatches `rustynetd macos-key-custody-check` and `validate_windows_key_custody` dispatches `rustynetd windows-key-custody-check` via `shell.run_argv`, each evaluating the report through the corresponding `evaluate_*_key_custody_report` function. Fail-closed behavior (invalid schema version rejected, dispatch errors attributed to the node) is asserted in the in-file tests.
- `crates/rustynet-cli/src/vm_lab/role_validation/runtime_acls.rs:42–70` — the same shape for `macos-runtime-acls-check` and `windows-runtime-acls-check`, evaluating through `evaluate_macos_runtime_acls_report` / `evaluate_windows_runtime_acls_report`.
- `crates/rustynetd/src/main.rs:355, 367, 427, 433` — the four daemon subcommands are registered: `windows-runtime-acls-check`, `windows-key-custody-check`, `macos-runtime-acls-check`, `macos-key-custody-check`. Implementation modules exist: `crates/rustynetd/src/macos_key_custody.rs` (doc comment at line 20: "Wired through the CLI as `rustynetd macos-key-custody-check`"), `crates/rustynetd/src/macos_runtime_acls.rs` (line 18), `crates/rustynetd/src/windows_key_custody.rs` (line 21: the `windows-key-custody-check` subcommand the orchestrator dispatches over). The `windows-runtime-acls-check` handler (`run_windows_runtime_acls_check_command`) lives directly in `main.rs`; no separate `windows_runtime_acls.rs` file exists.
- `crates/rustynet-cli/src/vm_lab/mod.rs:19255, 19585, 22808, 22856, 23065, 23100` — all six evaluator functions exist and are not stubs. Fail-closed unit tests for the Windows evaluators occupy `mod.rs:44459–44927` (accept an all-ok report; reject a drifted root, a missing root, an unknown schema version, an empty root list, an `overall_ok=true` inconsistent with per-root statuses, and malformed JSON). Linux evaluator tests occupy `mod.rs:49498–49596`.
- `crates/rustynet-cli/src/vm_lab/adapter/node_adapter.rs:532–568` — the `RoleValidatorKind` × platform dispatch table routes `RuntimeAcls` and `KeyCustody` for **all three** desktop platforms to the `validate_*` functions above.
- `crates/rustynet-cli/src/vm_lab/adapter/node_adapter.rs:259–272` — the default `supports_role_validator` returns `true` for Linux | macOS | Windows for every kind except `GossipConvergence` (which is gated by `gossip_convergence_runtime_implemented`). This is the **only** definition in `adapter/`; no per-adapter override exists.
- Therefore the per-node stages `KeyCustodyValidationStage` (`stage/key_custody_validation.rs`, fanout `PerNode`, reported-skips contract at lines 58–61 and 90–107) and `RuntimeAclsValidationStage` (`stage/runtime_acls_validation.rs`, fanout `PerNode`, reported-skips contract at lines 57–60 and 97–106) **execute** the macOS/Windows posture validators on mac/win nodes today. A mac/win node is not silently skipped at this layer; it runs the daemon check and the result is evaluated fail-closed.

### 1.2 What is genuinely Linux-only (confirms the coverage gap)

The **adversarial live stages** — the ones that actively attack a running daemon and validate rejection plus recovery, rather than sampling posture — dispatch exclusively to Linux test binaries:

1. **Adversarial key custody is Linux-only.** `crates/rustynet-cli/src/vm_lab/stage/live_key_custody_validation.rs:48–67` unconditionally runs:
   `cargo run --quiet -p rustynet-cli --features vm-lab --bin live_linux_key_custody_test -- --ssh-identity-file <id> --target-host <user>@<client-host> --report-path live_key_custody_report.json --log-path live_key_custody.log`
   There is no platform branch anywhere in the stage. The doc comment (lines 10–12) describes what the Linux binary does: manipulates key-file permissions on a running client daemon and validates rejection plus recovery. No `live_macos_*` or `live_windows_*` custody binary exists in `crates/rustynet-cli/src/bin/` (inventory checked 2026-09-01; only `live_linux_key_custody_test.rs`, `live_linux_secrets_not_in_logs_test.rs`, and `secrets_hygiene_gates.rs` are present for this family). There is no macOS chmod/ownership-downgrade rejection-plus-recovery live test and no Windows DPAPI/ACL tamper equivalent.

2. **Secrets-in-logs validation is entirely Linux-only — no mac/win variant exists at any layer.** `crates/rustynet-cli/src/vm_lab/stage/live_secrets_not_in_logs_validation.rs:45–64` unconditionally runs `--bin live_linux_secrets_not_in_logs_test` against the client node with report `live_secrets_not_in_logs_report.json` and log `live_secrets_not_in_logs.log`. Unlike custody and ACLs, there is **no** platform posture validator for secrets-in-logs either: `role_validation/` contains no secrets module (directory listing checked: admin_issue, anchor, authenticode, blind_exit, blind_exit_dataplane, dns_failclosed, exit_demotion_residue, exit_dns_failclosed, exit_nat_lifecycle, gossip_convergence, identity_challenge, ipv6_leak, key_custody, mesh_status, mod.rs, relay, runtime_acls, security_audit, service_hardening), and no per-platform secrets validator exists anywhere in `vm_lab`. `RoleValidatorKind` (`node_adapter.rs:75–86`) has no `SecretsNotInLogs` variant.

3. **Ledger mappings advertise coverage that does not run.** `crates/rustynet-cli/src/vm_lab/live_lab_run_matrix.rs` carries stage-name mappings `"macos_keychain_key_custody"` (line 212), `"windows_dpapi_key_custody"` (line 211), `validate_macos_runtime_acls → macos_runtime_acls` (lines 3767, 3880, 4884), `validate_windows_key_custody → windows_dpapi_key_custody` (line 4842), `validate_macos_key_custody → macos_keychain_key_custody` (line 4843), and mac/win rows for runtime-acls/key-custody/secrets stage names (lines 153–189, 240). These are ledger-attribution strings only. They are **not** evidence that the corresponding adversarial stages run on mac/win — the dispatch in 1.2(1) and 1.2(2) is unconditional and Linux-bound. This mirrors the run-matrix lesson in AGENTS.md §12.3: a column value is not proof; the stage's own report artifact is.

### 1.3 Documentation-drift finding (surfaced, not fixed — .rs edits are out of scope for this document)

Two stage doc comments contradict the dispatch code:

- `stage/key_custody_validation.rs:19–21` claims macOS/Windows nodes are "reported-skipped" behind a `key_custody_runtime_implemented` gate.
- `stage/runtime_acls_validation.rs:17–20` makes the same claim behind `runtime_acls_runtime_implemented`.

Both claims are stale on two counts: (a) the gates themselves (`key_custody_runtime_implemented` / `runtime_acls_runtime_implemented`, each file's lines 15–20) return `true` for all three desktop platforms; (b) `supports_role_validator`'s only definition (`node_adapter.rs:259–272`) does not consult those gates for `KeyCustody`/`RuntimeAcls` at all — it returns `true` unconditionally for desktop platforms. The skip branch in each stage is therefore dead code for mac/win today, and mac/win nodes run the posture validators, not a reported skip. Any implementation work under this design should correct those doc comments in the same change; this document does not (no `.rs` edits permitted here).

### 1.4 Windows prerequisite: the §4.7 identity-challenge gap

Every `run_role_validator` call passes through the §4.7 node-identity challenge (`node_adapter.rs:463–479` and `525–530`): the adapter must `collect_live_identity()` and match the expected node id, failing closed on `Unverifiable`, mismatch, or `NotLiveAssertion`. The Windows control CLI currently lacks the `status` subcommand needed to produce a live identity assertion, so Windows validators are gated behind a deferred gap (comment at `node_adapter.rs:519–524`). Until that gap closes, Windows posture validators cannot complete their §4.7 challenge in the lab regardless of anything this design adds. This design treats the gap as an explicit prerequisite, not something it works around.

### 1.5 Verdict summary

- **CONFIRMED:** the adversarial live stages for custody and all secrets-in-logs validation are Linux-only today; no macOS/Windows adversarial custody test exists; no secrets-in-logs validator of any kind exists outside Linux.
- **REFUTED (partially):** the unconditional claim of "Linux-only validators" — typed, fail-closed, per-platform posture validators for key custody and runtime ACLs already exist and execute on macOS and Windows through the `RoleValidatorKind` dispatch, backed by real daemon subcommands and tested evaluators.
- The gap this design closes is therefore specifically: **adversarial live custody validation on macOS and Windows, and secrets-in-logs validation on macOS and Windows at both the live and (new) posture layers.**

---

## 2. Design principles (inherited, not invented)

Everything below reuses the repo's existing patterns; no new validation philosophy is introduced.

1. **Fail-closed, adversarial by default.** Live stages must attack (mutate state, expect rejection, verify recovery), not merely sample. This is what separates `live_key_custody_validation` from the posture check: the posture check reports current modes; the live stage proves the daemon *rejects* a downgrade and *recovers*.
2. **Reported-skip, never silent pass.** When a stage cannot run on a node (wrong platform, unsupported capability), the node is named in a `*.reported_skips.json` artifact with a reason — exactly as `runtime_acls_validation.rs` and `key_custody_validation.rs` do today. A skip-only stage resolves to `StageOutcome::Skipped`, never `Passed`.
3. **One execution path.** No platform-conditional fallback that silently degrades. A mac/win adversarial test that cannot run must be reported-skipped at the stage layer, not approximated by a weaker check that still reports `pass`.
4. **Argv-only, no shell construction** with untrusted values (repo §4); any helper invocation follows `run_argv`.
5. **Verdicts come from stage report artifacts,** not ledger columns (AGENTS.md §12.3).

---

## 3. Design: adversarial live key-custody validation on macOS

### 3.1 Binary

New `crates/rustynet-cli/src/bin/live_macos_key_custody_test.rs`, mirroring the argument surface and report schema of `live_linux_key_custody_test` (`--ssh-identity-file`, `--target-host`, `--report-path`, `--log-path`), so the stage wiring and the failure formatter (`format_stage_binary_failure_with_log`, the QH-09 pattern already used in `live_key_custody_validation.rs:76–86`) work unchanged.

### 3.2 Adversarial sequence (what the test does)

The macOS daemon stores its private key material under its state directory (same custody model the Linux test attacks; the macOS custody posture module — `crates/rustynetd/src/macos_key_custody.rs` — defines the required modes/ownership the self-check enforces). The live test:

1. Establish a healthy baseline: daemon running as the configured node; `rustynetd macos-key-custody-check` over the control path reports `overall_ok = true`. Baseline failure aborts the test as `Failed` (attacking an already-broken node proves nothing).
2. **Attack:** via SSH, chmod the key file to a group/world-readable mode (the exact downgrade class the posture check forbids). Record the pre/post mode in the report.
3. **Expect rejection:** the daemon's custody watcher (or the next custody check it performs) must flag the drift. The test asserts either a daemon-side rejection event in the daemon log or a `drifted` status from a follow-up `macos-key-custody-check` — matching the rejection semantics the Linux binary asserts.
4. **Expect recovery:** after the daemon's remediation window (or an explicit operator-specified remediation step the test triggers, identical in spirit to the Linux binary's recovery phase), the key file mode is restored to the required mode and a final `macos-key-custody-check` reports `overall_ok = true`.
5. **No secret material is read, logged, or transmitted** at any step — only modes, ownership, and status booleans enter the report (repo §4 secrets hygiene; `secrets_hygiene_gates.sh` applies).

### 3.3 Custody-relevant ACL posture folded into the same run

Because macOS custody is file-permission + Keychain-adjacent, the test also records the custody directory's macOS ACL entries (`ls -le` on the state directory) before and after the attack, asserting the daemon does not loosen inherited ACLs during recovery. This is a posture observation inside the adversarial test, not a separate stage.

### 3.4 What this design deliberately does not do on macOS

- It does not attempt Keychain private-key extraction or import. Keychain custody on macOS is exercised by the daemon's own custody module; an adversarial test that reached into a user's login keychain would need interactive authorization and would violate the no-secret-material rule above. The Keychain linkage is validated by the existing `macos-key-custody-check` posture command; the live test attacks the file-mode surface, which is the surface the daemon enforces.

---

## 4. Design: adversarial live key-custody validation on Windows

### 4.1 Binary

New `crates/rustynet-cli/src/bin/live_windows_key_custody_test.rs`, same argument/report surface. Windows execution details differ:

- The daemon runs as a Windows service; the test drives it via the existing lab SSH plane (the `--node` engine already SSHes to Windows guests as `administrator`, per `ssh_params_for_role`, `live_key_custody_validation.rs:121–129`).
- All privileged operations (ACL reads/writes) go through `rustynet-windows-native` helpers invoked argv-only — never `icacls` shell strings built from untrusted values. Where an ACL probe is not already exposed by `rustynet-windows-native`, the prerequisite list in §8 requires adding it there (that crate is the sanctioned OS-boundary exception, repo §11.2).

### 4.2 Adversarial sequence

1. Baseline: `rustynetd windows-key-custody-check` reports `overall_ok = true` (DPAPI-wrapped key present, ACLs on the key file restrictive to the service account). Baseline failure aborts as `Failed`.
2. **Attack A (ACL downgrade):** grant `Users` read on the key file via the native ACL helper. Expect the daemon's custody watcher to flag drift; expect recovery restores the ACL.
3. **Attack B (DPAPI custody probe, passive):** copy (not move) the DPAPI-wrapped key blob to a temp path, then assert the daemon's next custody check still reports the service-profile binding intact and the test itself asserts it cannot decrypt the copy outside the service context (the blob is DPAPI-bound to the service account profile — the assertion is that a copy is inert, not that the test decrypts anything). No key material is emitted to logs; only hashes/sizes and status booleans enter the report.
4. Recovery: restore, final `windows-key-custody-check` reports `overall_ok = true`.

### 4.3 Blocking prerequisite (restated)

Per §1.4, Windows live stages cannot pass the §4.7 identity challenge until the Windows control CLI gains the `status` subcommand. The Windows custody test must be implemented behind a stage-level reported-skip (`NotLiveAssertion` observed → node named in reported-skips with that reason) so it is provably present but honestly skipped, never silently passing, until the prerequisite lands. This is the same fail-loud posture the parity roadmap mandates: live result = stage status; no dry-run-as-pass.

---

## 5. Design: secrets-in-logs validation on macOS and Windows (new surface)

Secrets-in-logs has no platform validator at all today (§1.2(2)). This design adds it at two layers, following the custody/ACL precedent.

### 5.1 New posture validator: `RoleValidatorKind::SecretsNotInLogs`

- Add a `SecretsNotInLogs` variant to `RoleValidatorKind` (`node_adapter.rs:75–86`) with per-platform dispatch entries routing to new `role_validation/secrets_not_in_logs.rs` functions `validate_linux_secrets_not_in_logs`, `validate_macos_secrets_not_in_logs`, `validate_windows_secrets_not_in_logs` (Linux included so the posture layer is symmetric with the existing live Linux binary).
- Each dispatches a new daemon self-check subcommand (`rustynetd secrets-not-in-logs-check`) that scans the daemon's own log sink for the repo's forbidden secret patterns (private-key block markers, enrollment-token shapes, share/preshared-key fields) and reports per-pattern booleans plus `overall_ok`, using the same report schema discipline (schema version, per-entry status, `overall_ok` consistency) the custody/ACL evaluators enforce.
- Evaluators `evaluate_{linux,macos,windows}_secrets_not_in_logs_report` land in `vm_lab/mod.rs` beside the existing six, with the same fail-closed test matrix (accept all-ok; reject drifted/missing pattern, unknown schema, empty pattern set, inconsistent `overall_ok`, malformed JSON).
- A `secrets_not_in_logs_runtime_implemented(platform)` gate (true for the three desktop platforms) is added and consulted by the default `supports_role_validator` **only if** the team decides this validator should start gated rather than live-by-default; the strictest practical default (repo rule) is to follow the existing `KeyCustody`/`RuntimeAcls` precedent: desktop-supported from day one, reported-skip only where the platform genuinely lacks support.
- A new `SecretsNotInLogsValidationStage` (fanout `PerNode`, reported-skips contract identical to the two existing posture stages) registers in `plan.rs` / `stage/mod.rs` beside its siblings.

### 5.2 New adversarial live stage: `live_secrets_not_in_logs_validation` per platform

Extend the live layer with per-platform binaries `live_macos_secrets_not_in_logs_test` and `live_windows_secrets_not_in_logs_test`, mirroring `live_linux_secrets_not_in_logs_test`:

1. Generate a marker-bearing trigger through the control path (the same benign secret-shaped stimulus the Linux binary uses).
2. Exercise the daemon pathways most likely to log: enrollment attempt, peer handshake, role transition rejection.
3. Fetch the daemon log (macOS: launchd-managed log path; Windows: the service's log sink) and assert no forbidden pattern appears.
4. Report per-check booleans; any hit is a hard failure (a secret in a log is never a warning).

The platform split lives in the binaries, not in a new stage dispatch: `live_secrets_not_in_logs_validation.rs` gains the same per-platform dispatch `live_key_custody_validation` gains in §6, so both live stages converge on one dispatch pattern.

### 5.3 Explicit non-goal

This design does not scan arbitrary application logs or system journals — only the daemon's own sink. Scoping the claim narrowly is what makes it honest and testable; a broader "no secrets anywhere in logs" claim is untestable and therefore not made.

---

## 6. Where each piece plugs in (stage/graph wiring)

| New artifact | Plugs in at | Depends on | Fanout |
|---|---|---|---|
| `live_macos_key_custody_test` / `live_windows_key_custody_test` binaries | `live_key_custody_validation.rs` dispatch: replace the unconditional Linux-only dispatch with per-platform dispatch (macOS → `live_macos_key_custody_test`, Windows → `live_windows_key_custody_test`, Linux → existing binary); a node whose platform has no binary is reported-skipped, never silently passed | unchanged (`LiveSecretsNotInLogsValidation`) | `Once` (unchanged) |
| `live_macos_secrets_not_in_logs_test` / `live_windows_secrets_not_in_logs_test` binaries | same dispatch pattern added to `live_secrets_not_in_logs_validation.rs` | unchanged (`LiveRebootRecoveryValidation`) | `Once` (unchanged) |
| `RoleValidatorKind::SecretsNotInLogs` + `role_validation/secrets_not_in_logs.rs` + daemon `secrets-not-in-logs-check` + evaluators | dispatch table `node_adapter.rs:532–568`; new `SecretsNotInLogsValidationStage` | posture stage: `ServiceHardeningValidation` (mirroring `KeyCustodyValidationStage`) | `PerNode` |
| Windows custody/secrets live tests | stage layer with reported-skip on `NotLiveAssertion` until the Windows `status` subcommand lands (§4.3) | — | — |

The dispatch change in the two live stages is the one place this design touches existing stage files; the reported-skip writer, outcome resolution (`failures → Failed`, `skips-only → Skipped`, else `Passed`), and failure formatting are reused verbatim from the existing stages.

---

## 7. Offline unit tests (written now; live proving pending lab availability)

All of the following run offline (no VMs), following the existing in-file test patterns:

1. **Dispatch tests** (in the two live-stage files' test modules): a stub adapter/shell host asserts that a Linux client node dispatches to `live_linux_key_custody_test`, a macOS node to `live_macos_key_custody_test`, a Windows node to `live_windows_key_custody_test`, and that a platform without a binary produces a reported-skip entry — never a `pass` outcome and never a silent no-op.
2. **Evaluator fail-closed matrices:** for each new `evaluate_*_secrets_not_in_logs_report`, the same six-case matrix the Windows custody evaluators use (accept all-ok; reject drifted entry, missing entry, unknown schema, empty set, inconsistent `overall_ok`, malformed JSON).
3. **Posture-stage tests:** the new `SecretsNotInLogsValidationStage` reported-skips artifact is written with per-node reasons; `outcome_for` returns `Failed` with any failure even when skips exist, `Skipped` when only skips exist, `Passed` only when every node executed and passed.
4. **Daemon self-check tests:** `rustynetd secrets-not-in-logs-check` unit tests feed crafted log fixtures (containing each forbidden pattern shape) and assert detection, plus a clean-fixture negative test.
5. **Windows-native ACL helper tests** (in `rustynet-windows-native`'s existing test conventions): grant/deny/revert round-trip on a temp file with the service-account SID shape — offline where the crate's existing tests allow, lab-gated otherwise.

**Live-proving status: none.** The lab VMs are down as of this design's date; every live assertion above (macOS chmod-downgrade rejection + recovery, Windows ACL/DPAPI attacks, cross-platform log scans) is pending a lab-available proving run on the Rust `--node` engine, with rows appended to `documents/operations/live_lab_node_run_matrix.csv` and verdicts taken from stage report artifacts per AGENTS.md §12.3. No parity claim is made or implied by this document.

---

## 8. Prerequisites and sequencing (owner-gated)

1. **Adversarial review of this design** (separate reviewer, not this document's author) — must precede any implementation.
2. **Lab availability** — live proving of every §3–§5 assertion.
3. **Windows control CLI `status` subcommand** — unblocks the §4.7 identity challenge; until then Windows live tests are implemented-but-reported-skipped (§4.3).
4. **Doc-comment correction** — the stale mac/win reported-skip claims in `key_custody_validation.rs:19–21` and `runtime_acls_validation.rs:17–20` (§1.3) are corrected in the implementation change that lands the first of the new validators.
5. **Staged landing order** (lowest risk first): (a) secrets posture validator + stage (new surface, no existing behavior touched); (b) per-platform dispatch in the two live stages + macOS binaries; (c) Windows binaries behind the §4.3 skip.

## 9. Parity alignment

This design exists to serve the `CrossPlatformRoleParityPlan_2026-06-21.md` mandate: no OS may be a capability limiter, and parity means live-proven parity on the `--node` engine of record, not posture parity alone. The custody/secrets/ACL cells on macOS and Windows are incomplete today in exactly the sense §1.2 establishes; this document specifies their closure path and refuses to overclaim: until §8 items 1–2 complete with green stage artifacts, the parity matrix entries for these cells remain unproven.
