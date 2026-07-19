# Documentation-vs-Code Discrepancy Audit — Re-Verified Against Current Repo (2026-07-18)

Date: 2026-07-18
Status: complete — 55 findings re-verified against current `main` (commit `41514ee`); 1 fixed and dropped, 54 remain applicable

## 0) What This Document Is

An earlier pass of this same audit (55 findings, DA-01 through DA-55) was run on 2026-07-17 against a **frozen snapshot** of this repo dated 2026-05-28 (`~/Rusty Suite/repos/Rustynet`, a separate directory with no git history — not this repo). That snapshot turned out to be ~7 weeks stale: this real repo has had substantial independent work land since, including a whole new "Cross-Platform Role Parity" + "Service Hosting Roles" (nas/llm) program, a new live-lab evidence engine, and a 2026-07-15 security/quality audit pass (`documents/operations/done/RustynetAuditFindings_2026-07-15.md`, `SecurityAuditFixes_2026-07-15.md`) — an unrelated lens (unwrap/expect fail-open paths, Debug-leak redaction, DPAPI ACL checks), not doc-accuracy.

Every one of the original 55 findings was independently re-verified against this repo's actual current code and docs before being included here. **Only findings still applicable survive below** — nothing carried forward on trust from the old pass. One finding (the original DA-16) turned out to be genuinely fixed and is not repeated here; see §5 for what changed and why it was dropped.

Read-only audit — no code was changed producing this document.

## 1) Summary Table

| ID | Doc | Severity | One-line finding | Status vs 2026-05-28 snapshot |
|----|-----|----------|-------------------|-------------------------------|
| DA-01 | SecurityMinimumBar.md | **Critical** | "TLS 1.3 enforced for control-plane APIs" — no TLS stack exists; a *new* self-asserted `tls13_valid=true` field is now hardcoded at issuance, unrelated to any real handshake | Confirmed, **worse** |
| DA-17 | CLAUDE.md §3 / boundary gate | **Critical** | WireGuard-boundary-leakage gate fails today (ran it live: exit 78) — 16 violations, up from 11 | Confirmed, **worse** |
| DA-36 | MembershipIncidentResponseRunbook.md | **Critical→High** | Selection-time revocation denial now works (fixed alongside DA-16), but an already-connected revoked peer's WireGuard config isn't torn down until daemon restart — `apply_revocation()` exists but is called only from tests | **Partially fixed**, real gap remains |
| DA-04 | NodeRoleTaxonomy.md | High | `capability add/remove` still hard-stubbed; still cites an already-landed schema as the blocker | Confirmed |
| DA-05 | AnchorNodeRoleDesign.md | High | `rustynet anchor init` still dry-run only | Confirmed |
| DA-18 | PrivacyRetentionPolicy.md | High | Zero deletion/expiry code anywhere; 3 of the doc's data classes still aren't populated by any code | Confirmed |
| DA-19 | PlugAndPlayTraversalRelayDeltaPlan.md | High | §8.2-8.5/§6.3 still claim relay transport unbuilt; code has grown further past it (relay daemon now 3,848 lines) | Confirmed, doc frozen while code moved |
| DA-20 | RustynetDataplaneExecutionPlan.md | High | Still claims `role set relay/anchor` is blocked by a nonexistent `RoleCliError::BlockedByCapabilitySchema`; code allows it and deploys real services | Confirmed |
| DA-26 | MacosLaunchdServiceManagement.md | High | Still wrong service labels, wrong LaunchAgent/LaunchDaemon type, wrong verification domain | Confirmed |
| DA-33 | DisasterRecoveryValidation.md | High | `restore state`/`--verify` still don't restore or verify anything | Confirmed |
| DA-34 | ProductionSLOAndIncidentReadiness.md | High | Still no instrumentation behind the numeric SLO targets; zero alerting integration | Confirmed |
| DA-35 | CompatibilitySupportPolicy.md | High | Compatibility/version-rejection policy still only exercised by its own unit tests | Confirmed |
| DA-37 | PolicyRolloutRunbook.md | High | `PolicyRolloutController` still has zero CLI/daemon wiring | Confirmed |
| DA-39/40 | ReleaseReadinessGuardrails.md | High | Still not CI-wired (only `bootstrap_ci_tools.sh` runs in CI); primary command still hardcodes a moved file path and still fails if run | Confirmed |
| DA-49 | CrossNetworkRemoteExitNodePlan.md | High | Still claims relay transport + WAN simultaneous-open unbuilt; both shipped and have grown further | Confirmed |
| DA-02 | CliCommandsDesign.md | High | Categories 8-14 still marked "Proposed Future," still fully shipped | Confirmed |
| DA-03 | CliCommandsDesign.md | High | Categories 1-7 "Completed" still describe two-word syntax that doesn't parse | Confirmed (one partial win: a real merged `logs` verb now exists, closer to doc's intent than before, still not the 3-verb split described) |
| DA-06 | Requirements.md | Medium | Policy engine still can't match its own `tag:servers:*` example | Confirmed |
| DA-07 | NodeRoleTaxonomy.md | Medium | Still lists 6 `IpcCommand` variants that don't exist in `ipc.rs` | Confirmed |
| DA-08 | CliCommandsDesign.md | Medium | `--json` still only works on `status`/`netcheck` | Confirmed |
| DA-09 | rustynet-control | Medium | Two capability enums still unreconciled — now explicitly *acknowledged* (a newer doc tells you to update both) but still not bridged | **Partially changed** |
| DA-10 | CliExitCodeTaxonomy.md | Medium | Still claims "70 binaries, no legacy exit(1) paths"; now 97 binaries, 13 still bypass it | Confirmed, **worse** |
| DA-11 | PlatformSupportMatrix.md | Medium | IPv6 parity row still mischaracterized as OS-based when it's backend-type-based | Confirmed |
| DA-21 | RustynetDataplaneExecutionPlan.md | Medium | D11.a "queued" vs "landed" contradiction still present — now traceable to a real code asymmetry (relay/anchor unblocked, `capability add/remove` still stubbed) | Confirmed, **more precisely characterized** |
| DA-22 | MembershipConsensus.md | Medium | Snapshot integrity still a self-computed checksum, not a signature | Confirmed |
| DA-23 | MembershipConsensus.md | Medium | Canonical encoding still ad hoc text, not CBOR/JSON as specified | Confirmed |
| DA-24 | Phase*Checklist.md (done/) | Medium | Checklist filenames still don't match their content's actual scope | Confirmed |
| DA-25 | Phase5.md / Phase5ReleaseReadinessChecklist.md | Medium | "Not release-ready" conclusion still holds, though the docs' cited root cause is itself now stale (a different gate now fails) | **Partially changed** |
| DA-27 | RustynetdServiceHardening.md | Medium | Same 2 mismatches (ExecStartPost command name, RuntimeDirectoryMode) | Confirmed |
| DA-28 | ComplianceControlMap.md / VulnerabilityResponse.md | Medium | `patch_sla_tracker.json` now exists on disk but is gitignored, empty, and nothing generates it | **Partially changed**, core problem unchanged |
| DA-30 | ADR-003-cli-exit-code-taxonomy.md | Medium | "100% coverage, ~71 binaries" claim still false; now 97 binaries, 21+ bypass | Confirmed, **worse** |
| DA-41 | ReleaseSigningRunbook.md | Medium | Still overstates PFX password safety; the false claim has now spread into the signing script's own docstring | Confirmed, **worse** |
| DA-42 | FinalLaunchChecklist.md | Medium | "Security Minimum Bar verified" checkbox still has no automated gate | Confirmed |
| DA-43 | VulnerabilityResponse.md | Medium | "Promote to stable only after gates pass" still not code-enforced | Confirmed |
| DA-48 | CrossNetworkRemoteExitNodePlan.md | Medium | Still claims a `rustynetd` compile break exists; compiles clean (verified live) | Confirmed, now ~6 months stale |
| DA-50 | UdpHolePunching{...}_2026-03-07.md (×3) | Medium | Superseded traversal algorithm still described as current in 2 of 3 docs; the 3rd got a partial self-correction at the top but its body section is still stale | **Mixed** — see detail |
| DA-51 | BackendAgilityValidation.md | Medium | Still claims no second non-simulated backend exists; unchanged since 2026-05-05 | Confirmed |
| DA-12 | PlatformSupportMatrix.md (toolchain) | Low | Release-side toolchain mismatch fixed; CI-side Windows-job mismatch still exists, now repo-wide via a shared constant | **Partially changed** |
| DA-13 | Multiple ops docs | Low | File:line citation drift continues (spot-checked: `daemon.rs` now 28,988 lines, citations rot faster than ever) | Confirmed |
| DA-14 | rustynet-control (undocumented) | Low | `RoleCapability::EntryRelay` still undocumented in all role docs, including the newest one | Confirmed |
| DA-15 | AnchorNodeRoleDesign.md / start.sh | Low | Still quotes wizard text that doesn't exist in the real `start.sh` | Confirmed |
| DA-29 | ADR-001-secret-log-audit.md | Low | Test-count drift widened (70 tests now vs. 67 claimed, was 69 at snapshot) | Confirmed, **worse** |
| DA-31 | TestCoverageImprovementPlan.md | Low | `roles.rs` table row still says "0 tests"; real count now 12 (was 9 at snapshot), file now 409 lines (was 147) | Confirmed, **worse** |
| DA-32 | RustynetDataplaneExecutionPlan.md | Low | Still under-claims Windows gateway detection as "stubbed"; it's real and wired | Confirmed |
| DA-38 | MembershipGovernanceRunbook.md | Low | Still cites a nonexistent test file; the crate now has a `tests/` dir (didn't before) but not the cited file | **Partially changed** |
| DA-44 | VulnerabilityResponse.md | Low | Evidence-recording claim still unimplemented; `artifacts/release/{inbox,raw}` still just `.gitkeep` | Confirmed |
| DA-45 | SecurityRegressionLessons.md | Low | Still cites a fabricated test name and a second test under the wrong name | Confirmed |
| DA-46 | SecurityPostureSummary.md | Low | Still self-contradicts on its own headline test count (2850 vs 2921) | Confirmed |
| DA-47 | SecurityPostureSummary.md | Low | Dead-code marker count claim (118) now off by 95 — real count is 213 | Confirmed, **much worse** |
| DA-52 | SerializationFormatHardeningPlan.md | Low | Still frames Phase B as migrated to `postcard`; `postcard` still isn't a dependency anywhere | Confirmed |
| DA-53 | WindowsWorkingNodeBringUpRunbook.md | Low | Example command still uses an invalid `--phase` value | Confirmed |
| DA-54 | WindowsWorkingNodeBringUpRunbook.md | Low | Still describes shipped Linux validators as missing, quoting a dead scaffold's comment | Confirmed |
| DA-55 | WindowsWorkingNodeBringUpRunbook.md | Low | Line-count citation gap widened — file now 1835 lines vs. the doc's claimed 1042 | Confirmed, **worse** |

## 2) Critical Findings (Detail)

### DA-01 — TLS control-plane claim still false, and a second self-asserted claim has appeared

`documents/SecurityMinimumBar.md:19` still states "TLS 1.3 enforced for control-plane APIs" with no status caveat. Verified: no crate directly depends on a TLS library — `rustls` only appears transitively via `ureq` in `crates/rustynet-mcp` (an LLM-API HTTPS client, unrelated to control-plane transport). `ControlPlaneTlsVersion`/`validate_negotiated_tls` (`crates/rustynet-control/src/lib.rs:167-235`) still just compares a caller-asserted enum — no negotiation, no socket, no certificate — and is still referenced only by its own unit tests. The anchor `bundle_pull` listener (`crates/rustynetd/src/daemon.rs:1245-1267`, `bind_anchor_bundle_pull_listener`) is still a plain `TcpListener::bind`, auth via bearer token only.

**New since the snapshot:** a `TrustEvidenceRecord.tls13_valid` field now exists (`crates/rustynetd/src/phase10.rs:324`, `daemon.rs:2289/11718`) and gets **hardcoded to `true` at issuance** regardless of any real transport (`crates/rustynet-cli/src/main.rs:8063`, plus 3 more call sites). Verification just checks the string parsed back to `true`. This is a second self-asserted, non-enforcing TLS claim layered on top of the original one — the gap has widened, not narrowed.

### DA-17 — WireGuard-boundary-leakage gate fails today, worse than the snapshot

Ran `cargo run --quiet -p rustynet-cli --bin check_backend_boundary_leakage` live against this repo: **exit code 78, `policy_reject`.** 16 violations (up from 11 in the snapshot): `crates/rustynet-crypto/src/lib.rs` (9 matches, up from a few), `crates/rustynet-control/src/credential_unwrap.rs` (2), `crates/rustynet-control/src/key_rotation.rs` (3), plus `crates/rustynet-backend-api/src/lib.rs` (2, newly noted). None of the originally-cited files have been cleaned up. The `SCAN_TARGETS` scope gap (excludes `crates/rustynet-cli`) is also worse — manually grepping that crate now returns **1,102 matches** (was "dozens"). This gate has had zero engagement since the snapshot; the unrelated 2026-07-15 security audit didn't touch it.

### DA-36 (was tied to DA-16) — partially fixed; a real gap remains on the teardown side

Good news first: DA-16 (the production membership-directory wiring gap) is **genuinely fixed** — `Phase10Controller`'s `set_membership()` is now called from 5 real paths in `daemon.rs`, and `check_peer_membership_active` (`phase10.rs:6079`) fails closed (Revoked/Unknown → denied). This part of `MembershipIncidentResponseRunbook.md`'s claim ("revoked node selection is denied") now holds — confirmed via `evaluate_with_membership` selection-time gates (`phase10.rs:5402,5478`; `daemon.rs:4254/4276/4291`).

But the runbook's other claim — that after revoke + reconcile, "**revoked node routes/peers are removed**" — does not hold for a peer that was already connected *before* revocation. `Phase10Controller::apply_revocation()` (`phase10.rs:5608`) is the only method that performs targeted, immediate peer teardown, and its own doc comment says it "does not wait for the next generation cycle" — but grepping all call sites shows it is invoked **only from test code** (`phase10.rs` unit tests, one `daemon.rs` test). The real `reconcile()` → `apply_dataplane_generation` → `apply_generation_stages` path (`phase10.rs:5177-5240`) is add-only: it iterates the desired peer list and gates new entries, but never diffs against the previous `managed_peers` set to tear down entries that dropped out. Net effect: if a revoked node is still in the next desired list, the *whole* generation apply fails closed (blunt, whole-node lockdown) — but if it's already been dropped from the desired list, its prior WireGuard config simply lingers un-torn-down until the next daemon restart. No test asserts the managed-peer set shrinks when a live peer's status flips to Revoked mid-session.

**Recommendation for the incident runbook:** the "confirm daemon behavior" step should distinguish "new selection of a revoked node" (now genuinely denied) from "immediate teardown of an already-connected revoked peer" (not yet wired to production reconcile) — the second still needs a manual verification step or a restart until `apply_revocation()` gets a real call site.

## 3) High Findings (Detail)

**DA-04 — `capability add/remove` still hard-stubbed.** `execute_capability` (`crates/rustynet-cli/src/main.rs:19476-19532`) still unconditionally errors for both verbs, citing the D11.a schema as "queued." `MembershipOperation::SetNodeCapabilities` remains extensively implemented in `rustynet-control/src/membership.rs` — the schema exists, the CLI verb still isn't wired to it. Confirmed the code comment literally reads "Always Blocked pre-D11.a" even though D11.a landed (see DA-21).

**DA-05 — `rustynet anchor init` still dry-run only.** `crates/rustynet-cli/src/anchor_init.rs` untouched since 2026-05-22; `build_anchor_init_plan` (line 39) still hard-errors at lines 43-47 unless `config.dry_run` is set.

**DA-18 — PrivacyRetentionPolicy.md still entirely unenforced.** Zero `DELETE FROM` anywhere in the codebase; `TamperEvidentAuditLog`'s `retention_days` field (`rustynet-control/src/operations.rs:151-290`) is still write-only, nothing prunes on it. `auth_events`, `diagnostic_metrics`, `credential_material_references` still have zero `.rs` hits under those names.

**DA-19 — PlugAndPlayTraversalRelayDeltaPlan.md §8.2-8.5/§6.3 frozen while code moved further.** `crates/rustynet-relay/src/main.rs` is now 3,848 lines (was 3,550), still a genuine production relay daemon — even more clearly contradicting the doc's "placeholder" framing. §8.1 in the same document got a "RESOLVED" annotation when D2 closed; §8.2-8.5 and §6.3 never did, byte-identical to the snapshot.

**DA-20 — Still under-reports shipped role-transition capability.** `RoleCliError::BlockedByCapabilitySchema` still doesn't exist as a type anywhere in the repo. `plan_concrete_actions` (`role_cli.rs:553`) still allows `role set relay/anchor` and dispatches `ConcreteAction::DeployRelayService` (line 882), confirmed by passing tests `target_relay_deploys_relay_service`/`target_anchor_deploys_relay_service` explicitly commented "unlocked by D11.a."

**DA-26 — MacosLaunchdServiceManagement.md still badly stale.** Same wrong labels (`com.rustynet.rustynetd*` vs real `com.rustynet.daemon`/`privileged-helper`), still claims a user LaunchAgent when the real unit is a system LaunchDaemon at `/Library/LaunchDaemons/`, still attributes plist generation to `start.sh` (real installer: `scripts/bootstrap/macos/Install-RustyNetMacosService.sh`).

**DA-33 — DisasterRecoveryValidation.md restore/verify still non-functional.** `execute_restore_state` (`main.rs:21256`) still only lists tar contents, still prints guidance to manually `tar -xf`. `verify` flag still echoed into JSON with no real check.

**DA-34 — No instrumentation behind SLO targets, still.** Relay metrics still just `active_sessions`/`allocated_ports` + forwarding counters (`rustynet-relay/src/main.rs:1040`). `phase1_baseline_metrics()` (`rustynetd/src/perf.rs:57`) still reads env vars. Zero alerting integration repo-wide (pagerduty/opsgenie/alertmanager/webhook — all zero hits).

**DA-35 — CompatibilitySupportPolicy.md enforcement still only in its own tests.** `CompatibilityPolicy`/`CompatibilityDecision` (`rustynet-control/src/ga.rs:24`) — still zero usage in `daemon.rs` or `rustynet-relay/src/main.rs`.

**DA-37 — PolicyRolloutRunbook.md describes an unwired control plane, still.** `PolicyRolloutController` still has zero references outside `rustynet-policy/src/lib.rs`. `parse_policy_command` still only handles `list`/`apply`/`test`; `apply` still just diffs and refuses to apply, pointing to `ops issue-and-distribute-assignments`.

**DA-39/DA-40 — ReleaseReadinessGuardrails.md still not CI-wired, still broken.** `release-windows.yml` no longer exists as a separate file (merged), but neither `release.yml` nor `cross-platform-ci.yml` invoke `release_readiness_gates.sh` — only `bootstrap_ci_tools.sh` runs in CI. `release_readiness_gates.rs:14` still hardcodes the moved `Phase5ReleaseReadinessChecklist_2026-04-12.md` path; the command still fails if run as documented.

**DA-49 — CrossNetworkRemoteExitNodePlan.md §4.2/§4.3 still claim relay/WAN unbuilt.** Both have shipped and grown further: relay daemon now 3,848 lines; `execute_ice_pair_race` (`traversal.rs:1860`) still wired from `phase10.rs:5843`, all 6 tests in `rustynetd/tests/ice_pair_race.rs` still pass (ran live).

**DA-02/DA-03 — CliCommandsDesign.md still wrong in both directions.** Untouched since before the 2026-05-28 snapshot per `git log`. Categories 8-14 still marked unbuilt despite all 10 parser functions existing in `main.rs` (now lines 20026-20232 in a 26,738-line file). Categories 1-7 "Completed" still describe two-word syntax that doesn't parse — real dispatch is still flagless single-token matches. One small change: a real merged `logs [--follow] [--level] [--lines]` verb now exists (`main.rs:2059`), closer to the doc's spirit than the snapshot's flagless version, but still not the doc's three-way `tail`/`errors`/`export` split.

## 4) Medium and Low Findings (Detail)

**DA-06 (Medium).** `selector_matches` (now `rustynet-policy/src/lib.rs:382`) still exact-string-or-`"*"` only; `Requirements.md:316` still shows the unmatchable `tag:servers:*` example; crate still has zero serde/toml deps.

**DA-07 (Medium).** `NodeRoleTaxonomy.md` §4.3 still lists 6 `IpcCommand` variants absent from `rustynetd/src/ipc.rs`'s real enum (`Status`, `Netcheck`, `StateRefresh`, `ExitNodeSelect`, `RouteAdvertise/Retract`, `KeyRotate/Revoke`, `PushGossipBundle`, `EnrollmentConsume`, `MembershipApply`, `Unknown` — none of the claimed 6).

**DA-08 (Medium).** `command_supports_json_render` (`main.rs:1792`) unchanged: `matches!(command, CliCommand::Status | CliCommand::Netcheck)`.

**DA-09 (Medium, partially changed).** `RoleCapability` (now 14 variants, added `ServesNas`/`ServesLlm`/`AnchorPortMappingPinned`) and `Capability` (now 9, added `ServesNas`/`ServesLlm`) remain unbridged at the original divergence points (`exit_server` vs `serves_exit`, `relay_host` vs `serves_relay`). The two new nas/llm variants use identical wire strings in both enums — better discipline going forward, but the underlying duality is now explicitly *documented* as intentional (`NodeRoleTaxonomyExtension_2026-06-11.md` §3.2 tells you to update both enums) rather than accidentally undocumented. Downgraded from "undocumented" to "documented but still unreconciled."

**DA-10 (Medium, worse).** Binary count now 97 (was 86); 13 binaries (was 11) still bypass `ExitCode` with raw `std::process::exit`.

**DA-11 (Medium).** `PlatformSupportMatrix.md` IPv6 row still framed as OS-based; still cites a dead `lib.rs:775-781` (file is 29 lines now). Real split confirmed still backend-type-based.

**DA-21 (Medium, more precisely characterized).** The D11.a "queued" vs "landed" self-contradiction in `RustynetDataplaneExecutionPlan.md` is unchanged, and now traceable to a genuine code asymmetry: D11.a unblocked `role set relay/anchor` (DA-20) but did **not** unblock `capability add/remove` (DA-04), which remains hard-stubbed with its own stale "pre-D11.a" comment.

**DA-22/DA-23 (Medium).** Snapshot self-checksum (not signature) and ad hoc `key=value` encoding (not CBOR/JSON) both unchanged in `rustynet-control/src/membership.rs`.

**DA-24 (Medium).** `done/Phase{1,2,3}Checklist` scope-vs-filename mismatch unchanged.

**DA-25 (Medium, partially changed).** "Not release-ready" conclusion still holds, but the specific blocker the docs cite is now stale — a newer gate artifact (`artifacts/release/phase5_gate_report.json`, ~2026-05-23) shows `cargo_test` now passing but `phase4_gates` now failing instead. No successful full release-gate run exists anywhere in `artifacts/`.

**DA-27 (Medium).** Same 2 mismatches (ExecStartPost command, RuntimeDirectoryMode 0700 vs real 0770) — both files unchanged.

**DA-28 (Medium, partially changed).** `patch_sla_tracker.json` now exists on disk but is gitignored (`.gitignore:37`), empty (`{"records":[]}`), and nothing generates/updates it. Core problem (no real pipeline) unchanged.

**DA-30 (Medium, worse).** ADR-003's "~71 binaries, 100% coverage" now further from reality: 97 binaries, 21+ bypass the taxonomy (was 11).

**DA-41 (Medium, worse).** `ReleaseSigningRunbook.md` still omits the argv-exposure caveat; the false "password never on command line" claim has now spread into `Sign-RustyNetWindowsBinary.ps1`'s own `.DESCRIPTION` docstring, directly contradicted by that same script's inline comment 15 lines later.

**DA-42 (Medium).** `FinalLaunchChecklist.md` checkbox still untied to any gate script.

**DA-43 (Medium).** `validate_release_track` (both copies) still just checks enum membership, never reads gate state.

**DA-48 (Medium).** `CrossNetworkRemoteExitNodePlan.md`'s compile-break claim still false — ran `cargo check -p rustynetd --all-targets` live, compiles clean in 12.5s.

**DA-50 (Medium, mixed).** Of the three UDP hole-punching docs: `UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md`'s top "Current Open Work" block was rewritten and now correctly says HP-2 is complete — but its body §2 is untouched and still describes the superseded one-sided probe loop. The other two docs (`ImplementationBlueprint`, `HP2IngestionPlan`) are fully unchanged, still describe the old algorithm and still cite the regression test as failing — ran it live, it passes.

**DA-51 (Medium).** `BackendAgilityValidation.md`'s "no second backend" claim still byte-identical to the snapshot; `rustynet-backend-userspace` unchanged since 2026-05-05.

**DA-12 (Low, partially changed).** Release-side toolchain mismatch is fixed (`release.yml` now uses the pinned version uniformly). CI-side Windows-job mismatch still exists, and is no longer Windows-specific — it now applies repo-wide via `bootstrap_ci_tools.rs`'s `PINNED_TOOLCHAIN`/`DEFAULT_SECURITY_TOOLCHAIN` constants. Still undocumented in ops docs.

**DA-13 (Low).** Citation drift continues; `daemon.rs` is now 28,988 lines and the one remaining `PlatformSupportMatrix.md` citation into it (`:526-530`) resolves to unrelated content — real target is now at `:2706`.

**DA-14/DA-15 (Low).** Both unchanged — `EntryRelay` still undocumented (including in the newest role doc); `start.sh` wizard text still doesn't exist in the real 29-line dispatcher.

**DA-29 (Low, worse).** `secret_log_audit.rs` now has 70 tests (was 69), ADR-001 and the gate script both still say 67.

**DA-31 (Low, worse).** `TestCoverageImprovementPlan.md`'s table row still says "0 tests"; `roles.rs` now has 12 tests (was 9 at the point a status note was added) across 409 lines (was 147) — the doc's own inline "Status 2026-05-27" note (landing 9 tests) was never reconciled with the summary table then, and still isn't now.

**DA-32 (Low).** Still under-claims — Windows gateway/interface detection (`port_mapper.rs:1120-1153`, `dataplane_candidates.rs:191-235`) is real and wired, doc still says "stubbed."

**DA-38 (Low, partially changed).** `rustynet-control/tests/` now exists (added 2026-07-02) with `membership_model_conformance.rs`, but the doc's specific citation, `membership_schema_golden_test.rs`, still doesn't exist.

**DA-44/DA-45/DA-46 (Low).** All unchanged — evidence-recording still unimplemented, fabricated test citation still uncorrected, self-contradictory test count still unreconciled.

**DA-47 (Low, much worse).** Dead-code marker count claim (118) is now off by 95 — real count via live grep is 213.

**DA-52/DA-53/DA-54 (Low).** All unchanged — `postcard` still not a dependency, invalid `--phase prepare-transport` example still present, dead Linux-validator scaffold still misquoted as current state.

**DA-55 (Low, worse).** `windows_command.rs` line-count citation gap widened to 793 lines (1042 claimed vs. 1835 actual, up from 1725 at the snapshot).

## 5) What Was Dropped (Fixed Since the Snapshot)

**DA-16 — membership-directory production wiring — FIXED.** The original finding: `Phase10Controller`'s membership directory was hardcoded empty in production, and `check_peer_membership_active` no-op'd on empty, so revoked nodes weren't blocked on the general peer-provisioning path. Current code: `set_membership()` is now called from 5 real production paths in `daemon.rs` (bootstrap, periodic reconcile, post-apply sync, the revocation-commit path itself), and `check_peer_membership_active` (`phase10.rs:6079`) no longer checks `is_populated()` at all — it fails closed by default (`Unknown → denied`, `Revoked → denied`, only `Active → allowed`). A test (`test_empty_membership_directory_denies_peer_provisioning`) exists specifically proving the old bug's inverse. This looks like separately-landed work, unrelated to the 2026-07-15 audit pass (which doesn't mention `Phase10Controller` or `MembershipDirectory` at all).

Note the residual gap on the *teardown* side of the same subsystem is real and is now tracked as DA-36 in §2 above — don't treat DA-16's fix as closing the whole membership-enforcement story.

## 6) Recommended Priority

1. **DA-01 and DA-17** are both Critical and both currently false security guarantees in `SecurityMinimumBar.md`/`CLAUDE.md` — same "documented as met, not actually enforced" shape as before, and both got measurably worse in the last 7 weeks, not better, despite unrelated engineering volume.
2. **DA-36** — narrower now than the original DA-16, but still a real gap: wire `apply_revocation()` into the actual reconcile path, or have reconcile diff `managed_peers` against the desired set and tear down drops.
3. High-severity operational-runbook findings (DA-33 DR restore, DA-37 policy rollout, DA-39/40 release gates) describe procedures operators would actually try to follow and can't — same priority logic as before.
4. Everything else is accumulating drift, not urgent, but worth noting the general pattern: **nothing in this list got fixed by incidental development activity over 7 weeks** except the one item (DA-16) that was apparently deliberately targeted. Docs don't self-correct; they need an explicit pass like this one, repeated periodically.
