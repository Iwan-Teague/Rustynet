<!-- Produced by a ten-dimension multi-agent review on 2026-09-08 at commit 993ecf7a.
     Every finding was attacked by an independent agent instructed to refute it and to
     default to refuted when uncertain: 41 claims filed, 12 refuted, 29 survived.
     UNTRUSTED OUTPUT - verify each finding against the real code before acting on it. -->

# Rustynet Security Review — Final Report

**Tree:** `993ecf7a` (2026-09-08), clean except untracked `target-lab/`.
**Method:** ten dimensions, each finding then attacked by an independent agent trying to refute it. 41 claims filed, 12 refuted outright, 29 survived, 28 after merging one duplicate. Severities below are the post-verification values, not the filing agent's.

---

## 1. Verdict

**The production security core is in good shape. The machinery that proves it is not.**

Nothing here is a release blocker. Five findings were filed as blockers; all five were downgraded on verification — every one of them turned out to be gated by a compensating control the filer missed (a startup preflight, a dependency cascade, a fail-closed loader, an installer ACL, a default-off cargo feature). That is the shape of a codebase with real defense in depth: the single-point claims kept dying against a second layer that was actually there.

What survives clusters into two very different piles. The first is a small set of genuine gaps in production trust and dataplane paths — an owner-signature list missing two operations, a Windows command runner that cannot see a failed command, a Windows daemon that silently downgrades an irreversible security role. Four findings, all High, all fixable in a day each.

The second pile is larger and more consequential in aggregate: **8 of 28 findings are defects in the verification layer itself** — tests that cannot fail, gates that pass on nothing, lab stages that record green with no data behind the verdict. None of them break a running node. All of them mean that a claim of "proven" in this repository is worth less than it reads. Given that the release gate here is a live-lab evidence ledger, that is the finding that matters most, and it is the one the ledger's own QH-07 entry already half-anticipates.

The refutations are as informative as the findings. Reviewers systematically over-claimed reachability: they read a code path and asserted an attacker could drive it, without checking whether the shipped installer, the startup preflight, or the stage dependency graph admits that input. In this repo, they usually do not.

---

## 2. Surviving findings

### HIGH

**H1 — `requires_owner_signer` omits `AddNode`/`RemoveNode`, so a non-owner quorum can rewrite capabilities and defeat `blind_exit` immutability**
`crates/rustynet-control/src/membership.rs:463` · trust-state

The guard lists `RotateApprover`, `SetQuorum`, `SetNodeCapabilities`, `RotateNodeKey`. The `AddNode` reducer (`:2069-2092`) writes *both* capabilities and `node_pubkey_hex` — the two conditions the guard's own doc comment gives as its reason for existing — behind only a `BlindRelay` check. `RemoveNode` (`:2126-2132`) is a bare `retain`. Reproduced against the real crate through the shipped public API: with 1 Owner + 2 Guardians and quorum 2, signing with the two guardians only, a direct `SetNodeCapabilities` is correctly refused (`blind_exit is immutable`), but `RemoveNode` then `AddNode` succeeds — same `node_id`, same `node_pubkey_hex`, `blind_exit` gone, `anchor.bundle_pull` + `anchor.enrollment_endpoint` granted. Both halves are CLI-reachable (`membership propose-remove` `main.rs:5869`, `propose-add` `:5845`). This is exactly what SecurityMinimumBar 6.C forbids.

The remove step is not even required for the general case: plain `AddNode` already admits a node carrying `ExitServer`/`anchor.*` with no owner signature.

*Bounds:* not reachable in the default posture (genesis mints one Owner at quorum 1, so every quorum includes the owner; reaching the vulnerable approver set itself needs owner-signed `RotateApprover` + `SetQuorum`). Requires a colluding quorum of authorized approvers. For the `blind_exit` headline specifically, `validate_node_role_membership_alignment` (`daemon.rs:2397`) refuses a locally-blind_exit node whose membership carries `Anchor`, so the physical node does not begin serving — what is rewritten is the mesh-wide record.

*Fix (owner decision, not a one-liner):* do **not** blanket-add both arms — that makes every enrollment owner-signed, and `I4GossipImplementationHandoff_2026-08-05.md` D5 explicitly warns against extending this list on an agent's judgement. Split it: an owner-free `AddNode` restricted to a capability set that is exactly `{Client}`; owner required for any `AddNode` carrying `exit_server`/`anchor.*`/`serves_*`, or reusing a `node_id` the log shows was removed. Add explicit removal tombstoning so an id/pubkey pair cannot silently re-enter with a different grant.

---

**H2 — Windows backend command runner discards process exit status: every failed `wg`/`netsh`/`wireguard.exe` call reports success**
`crates/rustynetd/src/daemon.rs:3753` · backend-boundary

`WindowsHostWireguardRunner::run_capture` builds `WireguardCommandOutput` from stdout/stderr and never reads `output.status`; the struct has no status field. Both siblings check it (`linux_command.rs:105`, `daemon.rs:3704`). `run()` is `let _ = self.run_capture(...)?`, so every mutating command inherits the blindness. Production-wired via `--backend windows-wireguard-nt` → `daemon.rs:4031`.

Consequences: `remove_peer` (`windows_command.rs:517`) proceeds to `self.peers.remove(node_id)` on a failed `wg set … peer … remove`, defeating the invariant its own comment states verbatim — the daemon believes a revoked peer is gone while the live tunnel still serves its allowed_ips. `add_os_route`/`delete_os_route` failing makes `set_exit_mode(FullTunnel)` return Ok, so the daemon reports a client as tunnelled while default traffic leaves in the clear. `apply_peer_runtime` (`:369`) issues `wg set … endpoint … allowed-ips` through the same blind path, so peer installation and allowed-ips narrowing are equally unverified. The crate's unit tests drive `RecordingRunner`, a stub returning Ok for everything, and therefore cannot distinguish the two runners.

Partial mitigation: `remove_peer` calls `sync_persistent_config`, which rewrites the on-disk config without the peer — but it does not restart the service, so the live tunnel keeps serving the revoked peer until an unrelated restart.

*Fix:* add a status field (or check inline) and mirror `LinuxCommandRunner::run_capture` — `BackendError::internal` with exit status and trimmed stderr. **Caution:** `netsh … delete route` and `wireguard.exe /uninstalltunnelservice` exit non-zero when the object is already absent, so those need explicit absent-is-success handling. Add a test with a non-zero-status runner asserting `remove_peer` leaves the peer in `self.peers`.

---

**H3 — Windows daemon silently discards the `blind_exit` flag and installs a full NAT exit, then asserts the inverted posture as PASS**
`crates/rustynetd/src/phase10.rs:6572` · platform-parity

`WindowsCommandSystem::apply_nat_forwarding` takes `_blind_exit: bool` and drops it, calling `apply_windows_exit_nat_forwarding` (`:6190`), which enables IPv4 forwarding on **both** the tunnel and the underlay NIC and creates a masquerading `New-NetNat`. Linux (`:3346`) and macOS (`:5146`) both branch on the flag. `assert_exit_serving` (`:6849`) then *requires* that posture — `WINDOWS_PS_ASSERT_NAT` + `WINDOWS_PS_ASSERT_FORWARDING_ENABLED` — so the stage reports green precisely because the posture is inverted. `daemon.rs:2300` parses `blind_exit` on every platform; there is no `windows_blind_exit.rs`.

Reachability: the operator surfaces do reject it (`rustynet-operator/src/role.rs:90` + `config/validate.rs:376`), and `rustynet role set` cannot flip into blind_exit. But `windows_service.rs:197` reads a raw argv JSON array from the env file and hands it straight to the daemon — operator validation never runs there — and the shipped `Install-RustyNetWindowsService.ps1:11` declares `[string]$NodeRole = 'client'` with **no `ValidateSet`**, threading it into the args JSON at `:744`/`:756`. So `-NodeRole blind_exit` is a reachable shipped path.

Also note doc/code drift that strengthens this: `CrossPlatformRoleParityRefresh_2026-07-23.md:427` claims "Windows blind_exit — hard-excluded by design (main.rs hard-error)". No such hard error exists in `crates/rustynetd/src/main.rs`.

*Fix:* take `blind_exit: bool` and, until a real Windows blind_exit dataplane exists, return `SystemError::NatApplyFailed("blind_exit is not supported on Windows")` before any NAT work. Mirror it in `assert_exit_serving`. Add `[ValidateSet('client','admin','anchor','exit','relay')]` to the installer parameter.

---

**H4 — `traffic_test_matrix` drops its own duplicate-mesh-IP guard at the deadline, turning the mesh matrix into passing self-pings**
`crates/rustynet-cli/src/vm_lab/orchestrator/stage/traffic_test_matrix.rs:66` · lab-validators

`if (!has_collision && !has_missing) || Instant::now() >= deadline` — at the deadline the colliding map is committed and `has_collision` is computed and then never used again. No error, no outcome change. The asymmetry matters: `has_missing` still fails closed downstream (`:124` pushes "no mesh IP for X"), but a collision leaves a *fully populated* map, and the ping loop only skips `peer_alias == src_alias`, never comparing `peer_ip` to the source's own address. Every node then pings its own address, `ping` exits 0 (the killswitch carries `oifname "lo" accept` as a required fragment), `parse_ping_result` returns `Reachable`, `src_reached_peer` becomes true so the default-deny probe is judged conclusive, and line 207 returns `Passed` — full-mesh green, zero packets between nodes. Nothing is written on the pass path either; `capture_failure_state` runs only in the failure arm.

Not hypothetical: commit `3b3017fa`, which added this very guard, records the observed condition ("Both nodes reported 100.64.0.1").

*Fix:* at deadline expiry return `Failed` (or `NotProven { Unattributable }`) naming the duplicated address and the sharing aliases; additionally refuse any probe whose target IP equals the source's own. Write `traffic_test_matrix.evidence.json` on the pass path.

---

### MEDIUM

**M1 — macOS runtime `assert_killswitch` is a substring presence check, not a precedence check; the fixed evaluator exists and is never called from it**
`crates/rustynetd/src/phase10.rs:5544` · daemon-failclosed + platform-parity *(two dimensions found this independently; merged)*

`if !output.stdout.contains(MACOS_PF_TERMINAL_BLOCK_RULE)` is the entire default-deny assertion. pf is first-match-wins with `quick` short-circuit, so a single `pass out quick` above the terminator makes `block drop out quick all` unreachable while its text is still present in the dump. This is the last gate before the generation commits (macOS defines no `assert_exit_policy` override, so the trait default at `:817` routes here from `:7794`).

The repo names this failure itself: `macos_exit_killswitch_precedence.rs:164-186` says the substring form "credits a ruleset that leaks everything… this function was their alibi", and exports `evaluate_macos_killswitch_rules` as the fix. Linux does call the equivalent (`:2508`, RN-27); macOS blind_exit does (`macos_blind_exit.rs:161`); the macOS killswitch assert does not — the fixed validator runs only in the offline report binary (`main.rs:2656`).

**Ledger integrity note:** `AdversarialSecurityRemediation_2026-07-29.md:349` marks PF-05 **DONE at `8417edf1`**, and PF-05's own text names `phase10.rs`. `git show --stat 8417edf1` touched only the two precedence modules and never `phase10.rs`. Of the four S2 sites, Linux (`c047358f`), Windows (`d40323e8`) and macOS blind_exit (`7af2f0e0`) all got daemon-side fixes; the macOS killswitch assert is the one that did not, while the ledger reads closed.

*Bounds:* the daemon never authors pf text — `macos_pf_load_spec.rs:222` rejects any load whose last non-empty line is not the terminator, which is stronger than presence and runs on every load. The residual window needs root writing into the anchor post-load.

*Fix:* not a drop-in. `apply_nat_forwarding` (`:5168`) sets `allow_egress_interface = true` for every non-blind exit and every full-tunnel client, so the renderer legitimately emits a broad `pass out quick on en0`, which `classify_pf_egress_rule` scores as `Escapes`. Linux survives this only via its `acknowledged_wide_open` parameter; the macOS evaluator has none. Add that parameter, then wire the call. (The broad rule itself is PF-01, separately open.)

---

**M2 — Windows `block_all_egress` reports success while discarding the operations that close it**
`crates/rustynetd/src/phase10.rs:6888` · daemon-failclosed

`let _ = rustynet_windows_native::remove_wfp_tunnel_permit();` plus two discarded netsh deletes, then `Ok(())` unconditionally. `force_fail_closed` therefore always reaches `transition_to(FailClosed)` — the daemon reports FailClosed while the ALE_AUTH_CONNECT hard permit for the tunnel LUID may still be live. Linux (`:3679`) and macOS (`:5615`) both `map_err` into `BlockEgressFailed`, and the contract test at `:15775` that asserts this ordering is vacuous for Windows because the Windows arm cannot return Err past `:6882`.

*Correction to the claim, and it changes the fix:* only the WFP call is fixable. `WINDOWS_KS_RULE_TUNNEL` is never created anywhere (grep shows only deletes), so its delete always returns "No rules match"; `WINDOWS_KS_RULE_EGRESS`'s delete legitimately fails when no SSH CIDRs / WG port / traversal endpoints are configured. `?`-ing either would make `block_all_egress` fail on every Windows node and `force_fail_closed` would never reach FailClosed at all — strictly worse.

*Fix:* `map_err` on `remove_wfp_tunnel_permit()` only; keep `let _ =` on the two netsh deletes **with a comment saying why**. Optionally verify with the existing `wfp_tunnel_permit_present` read-back.

---

**M3 — macOS blind_exit node: `block_all_egress` is a complete no-op, then the daemon transitions to FailClosed**
`crates/rustynetd/src/phase10.rs:4161` · daemon-failclosed

`MacosPfLoadSpec::BlindExit { config }` carries no `strict_fail_closed` field, so `apply_pf_rules(true)` on a blind_exit node re-loads byte-identical rules. `MacosCommandSystem::block_all_egress` (`:5613`) *is* `self.apply_pf_rules(true)`. `blind_exit_pf_config` is never cleared on any fail-close path (`:5196`, `:5130`, `:7984` all deliberately preserve it), and the only clear site (`:5167`) is unreachable for a blind_exit node. `render_pf_rules` (`:4073`) drops the flag identically. No test covers `render_pf_rules(true)` with a blind config.

*Correction:* the claim's "ordinary forwarding ruleset" is wrong — the retained anchor is the hardened blind_exit posture, already stricter than the non-strict killswitch. And Linux behaves the same way (`LinuxCommandSystem::block_all_egress` appends a drop to a chain that already has `oifname <tunnel> accept` ahead of it and never touches the `forward` chain), so this is a shared gap in what `block_all_egress` means for a forwarding role, not a macOS regression. Retaining the anchor across fail-close is deliberate and tested.

*Fix:* add `strict_fail_closed` to `MacosPfLoadSpec::BlindExit` and a strict render/verify pair that suppresses the two tunnel passes and the mesh final-hop pass. Consider the same for Linux's forward chain.

---

**M4 — RSA-0008 issuance membership gate is dead code: no shipped caller installs a membership directory, and the empty directory disables the gate**
`crates/rustynet-control/src/lib.rs:3510` · policy-acl

`if self.membership_directory.is_populated() && !(…Active…)` — the whole revocation clause is skipped when empty, falling back to the membership-blind evaluator. `set_membership_directory`/`with_membership_directory` have **zero non-test callers**; all three shipped issuance sites (`rustynet-cli/src/main.rs:6854`, `:6961`, `:7052`) are bare `ControlPlaneCore::new`. The crate's own test at `:8065` pins the bypass as intended. All six issuance gates inherit it.

*Bounds:* real containment exists — the daemon twin `check_peer_membership_active` (`phase10.rs:8846`) denies Unknown/Revoked with no `is_populated` escape and has genuine production callers, so a revoked node named in an operator bundle is dropped at apply. The actor is the operator already holding the signing key. **This is a duplicate:** already open as RSA-0008 (`SecurityAuditLedger_2026-06-18.md:969`, Medium), with the "gate never runs" delta already recorded at `AdversarialSecurityReview_2026-07-29.md:394` and awaiting an owner decision at `AdversarialSecurityRemediation_2026-07-29.md:142`.

*Fix:* wire the directory at the three CLI sites from the same signed snapshot the daemon uses, delete the `is_populated()` short-circuit so absent ⇒ deny, and replace the pinning test with one asserting an empty directory **denies**.

---

**M5 — macOS key-custody verifier never checks passphrase custody; the lab reports it as verified**
`crates/rustynetd/src/macos_key_custody.rs:158` · crypto-custody

`build_entries()` is five file/dir probes — no Keychain read anywhere in the module, despite the header claiming "passphrase custody must use the reviewed macOS Keychain account path". Both siblings positively assert the passphrase artifact (`linux_key_custody.rs:205`, `windows_key_custody.rs:144`). The lab stage is labelled `macos_keychain_key_custody` and reports "macOS key custody verified … 5 reviewed artifacts checked" from that keychain-blind set. `LiveLabCrossPlatformCustodySecretsAclStageDesign_2026-09-01.md:104` asserts "The Keychain linkage is validated by the existing macos-key-custody-check posture command" — false against the code.

*Corrections:* the missing-item state is not silently reachable — `validate_passphrase_permissions` (`daemon.rs:14193`) routes into `read_passphrase_from_macos_keychain` with no file fallback and hard-errors, so the node cannot start. And *something* asserts the account: `evaluate_macos_launchd_environment` (`macos_service_hardening.rs:265`) pins the service name and requires the account env var. What genuinely remains unasserted is item **existence** at that service/account, and that it resolves from the System keychain rather than a user keychain (`rustynet-crypto/src/lib.rs:768` tries the default search list first).

*Adjacent gap found in verification:* macOS keeps a plaintext passphrase at rest at `/usr/local/var/rustynet/bootstrap/wireguard.passphrase` (`macos_install.rs:1924`), a path this verifier's "plaintext passphrase forbidden" probe does not cover — it checks only the legacy `keys/` path.

*Fix:* add a presence-only positive probe (never the bytes) via `load_macos_generic_password_system_keychain_owned`, pin the canonical entry count as `linux_key_custody.rs` does, and extend the forbidden-plaintext probe to the bootstrap path.

---

**M6 — Windows secret-ACL gate is a three-name denylist and does not reject a NULL DACL, for the LocalMachine-DPAPI passphrase blob**
`crates/rustynetd/src/windows_paths.rs:333` · crypto-custody

For a file the only structural requirement is `sddl.contains("D:")`, plus a denylist of exactly `["WD","AU","BU"]`. This is the check reached for the passphrase blob (`key_material.rs:281`, `windows_key_custody.rs:236`). A DACL granting `(A;;FA;;;IU)`, `(A;;FA;;;AN)`, or a named local SID passes; so does `D:NO_ACCESS_CONTROL`, which contains no ACE at all. Because DPAPI here is `LocalMachine`, any local process that can read the blob can `CryptUnprotectData` it. `rustynet-crypto/src/lib.rs:996` states plainly that the NTFS ACLs *are* the access boundary.

The repo already admits it twice: the test comment at `windows_paths.rs:1150` ("AN is not in FORBIDDEN_WELL_KNOWN_SDDL_PRINCIPALS today"), and `WindowsSddlBroadPrincipalAnalysis_2026-09-04.md`, which analyses the identical denylist in rustynet-crypto and names `windows_paths.rs` in §5.4 as carrying the same gap.

*Corrections:* the `D:P`-on-files half is deliberate (a file inside a protected parent inherits `D:AI`, never `D:P`, pinned by name in a test), and the directory-level exposure *is* caught by `validate_windows_runtime_startup_acls`, which fail-closes the daemon. The raw-SID variant is unreachable — SDDL normalises S-1-1-0/S-1-5-11/S-1-5-32-545 back to WD/AU/BU before the match. Reaching the bad state requires admin. What survives is that this gate fails **open on exactly the drift it exists to detect** — an admin misconfiguration or a `robocopy /copyall`-style restore.

*Fix:* the one the repo's own doc proposes — parse the trustee field per ACE and allowlist `SY`, `BA`, `S-1-5-80-*`, rejecting anything unrecognised; reject `NO_ACCESS_CONTROL`. Keep `sddl_ace_matches`' exact ACE-type parsing so a deny ACE is not misread as a grant.

---

**M7 — `DaemonBackend` never dispatches `peer_path_sample`, so the FIS-0013 path-quality re-race is inert on both userspace backends**
`crates/rustynetd/src/daemon.rs:4078` · backend-boundary

The `impl TunnelBackend for DaemonBackend` block defines 17 methods; `peer_path_sample` and `peer_path_health` are not among them, so both resolve to the `Ok(None)` trait defaults even though `userspace_shared/mod.rs:516` and `userspace_shared_macos/mod.rs:606` implement them for real. `poll_path_quality` (`daemon.rs:7939`, called unconditionally from the reconcile loop) therefore takes its `else { continue; }` for every peer on every tick; `ingest_sample` is never called and the quality-triggered re-race never fires. Both userspace variants are constructed from real production config in `from_config`.

Not gated off: FIS-0013's plan specified a `path_quality_rerace_enabled` flag defaulting off — that flag does not exist in the code, and the planned contract test was never written, which is why the suite stays green.

*Correction:* only the `peer_path_sample` half is load-bearing; `peer_path_health` has zero callers anywhere. The failure direction is safe by design ("no data is no signal, never a fabricated Healthy") — what is lost is a proactive re-race of a degraded Direct path, not a fail-open.

*Fix:* add both dispatch arms, and extend the source-text pin `daemon_backend_impl_dispatches_initiate_peer_handshake_to_variants` (`:24826`) to iterate every default-bodied trait method rather than one hardcoded name — otherwise the next added default repeats this exactly.

---

**M8 — Named-test evidence gate passes vacuously: `cargo test` with a filter matching nothing exits 0**
`crates/rustynet-cli/src/ops_ci_release_perf.rs:2057` · backend-boundary

`run_logged_test` checks only `output.status.success()`. Its callers pass hardcoded test-name lists (the ten-entry `probe_security_tests` at `:1247`, the backend blocker pair at `:1302`). Measured: `cargo test -q -p rustynet-backend-api --lib tests::this_test_does_not_exist_at_all -- --exact` prints "0 passed; 5 filtered out" and exits 0. Rename or delete any of those tests and the gate still exits 0, the run returns `Phase 10 HP2 traversal gates: PASS`, and an evidence report is written. Those reports are then folded into the phase10 **signed provenance** set (`ops_phase9.rs:2296`, `:4430`), and the writer hardcodes `"status":"pass"` and a `validated_by_tests` list that already drifts (9 names listed vs 14 executed).

The repo already implements the correct check and does not use it here: `execute_ops_verify_required_test_output` (`ops_phase9.rs:4859`) fails when `total_passed < 1`.

*Fix:* parse the harness summary in `run_logged_test` and require `N >= 1`, or run the filter once with `--list`. Also add the missing `windows_backend_reports_transport_socket_identity_blocker` test — `windows_command.rs:567` has the override with no test anywhere.

---

**M9 — blind_exit's Linux forwarding proof passes on any non-empty stdout from a command that always prints**
`crates/rustynet-cli/src/vm_lab/orchestrator/role_validation/blind_exit.rs:71` · lab-validators

`iptables -t nat -L POSTROUTING || nft list ruleset`, then `if stdout.trim().is_empty() { Err }`. Run under `sudo -n` as root, `iptables` always emits the chain header, and the `nft` fallback is always non-empty because the killswitch table is always present — so the guard can never fire and the Linux arm degenerates to "the daemon self-reports `node_role=blind_exit`". The probe is also semantically inverted: a correct blind_exit must have **no** NAT translation, so listing the NAT POSTROUTING chain measures nothing. The unit test `linux_fails_closed_when_no_forwarding_rules` (`:189`) feeds `stdout: Vec::new()`, an output the real command cannot produce, so it would still pass with the guard deleted.

*Bounds:* all five recorded `blind_exit` stage rows are macOS, so no false Linux green has been written yet — latent, not realized. A stronger sibling (`BlindExitDataplaneValidationStage`, with named subchecks) is in the same plan but cascade-skips behind `ExitDemotionResidueValidation`.

*Fix:* delegate to `evaluate_linux_blind_exit_dataplane_report`, or assert the named mesh-scoped forward rule. Rewrite the test with real header-only output. Also reconcile the macOS arm (`:93`), which demands pf NAT rules be **present** — contradicting the `no_nat_translation` subcheck the dataplane evaluator requires for the same role.

---

**M10, M11, M12 — three source-text pins that cannot fail** · test-integrity

All three use `include_str!` on the file containing the test module, so each needle matches its own assertion line. All three were confirmed by actual mutation, not inspection.

- `crates/rustynetd/src/linux_killswitch_boot.rs:1343` — all three needles of `boot_killswitch_source_contains_traversal_endpoint_rule` self-match; deleting production lines 404-420 (the entire per-endpoint STUN allow loop) leaves the test green. The chain hooks `output` at priority 0 with `policy drop`, so the reverted state vetoes every STUN datagram and NAT traversal becomes impossible — the regression the test's own comment records from a real two-network lab. A narrower mutation (drop the `daddr`/family tokens, keep the loop) is clippy-clean, compile-clean and test-green, and converts the pinhole into a blanket `udp dport <port> accept`. The sibling WG-listen-port pin is 3/4 vacuous the same way.
- `crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs:1396` (and the macOS twin at `userspace_shared_macos/runtime.rs:1550`) — the only guard that the worker loop drives boringtun's clock. I deleted the production call at `:1221`, rebuilt on the pinned toolchain, and the test **passed**; the full crate suite passed 292/292. Reverted, boringtun's clock freezes, `path_live_peer_count` reads 0 while traffic flows, and keepalives stop — the incident the comment documents at 6.94 Mbit/s. The only other coverage calls the method directly, never the loop; macOS has none at all.
- `crates/rustynet-cli/src/ops_install_systemd.rs:3116` — the literal `/var/lib/rustynet/credentials-workspace` appears in a rationale comment, the assertion, *and* the failure message, so deleting the production provisioning at `:179` leaves three self-satisfying occurrences. Without that directory the membership-mutation ops verbs fail closed on every non-e2e install (`ops_e2e.rs:2449`), a condition already recorded failing a real run in `MacCellsHarvest_2026-08-28.md:1599`.

*Fix:* see systemic pattern **A** below — fix the class, not the three instances.

---

### LOW

| # | Finding | File:line | Why low |
|---|---|---|---|
| L1 | Linux runtime-ACL stage trusts `overall_ok`; macOS and Windows both cross-check it against per-root statuses | `rustynet-cli/src/vm_lab/mod.rs:23444` | Lab-only, default-off feature; unreachable via the real producer (`overall_ok` is an AND over the same vector); downstream stages re-check independently. Four-line paste from the Windows sibling + the two tests Linux lacks. |
| L2 | Windows arm of `validate_key_custody_permissions` does no ownership check while its comment claims parity with the unix owner-only check | `rustynet-crypto/src/lib.rs:1896` | Daemon path *is* owner-checked by `validate_windows_runtime_startup_acls`; already recorded as F2.b in `WindowsFixesSecurityReview_2026-09-04.md`. Residual: the `rustynetd` subcommand paths (`main.rs:4149`, `:4688`) take an operator `--signing-key` and skip that gate. Fix the comment at minimum. |
| L3 | NAS at-rest key and LLM-gateway signing key validate mode but not owner, and have no non-unix arm | `rustynet-nas/src/main.rs:223`, `rustynet-llm-gateway/src/main.rs:194` | LLM half is inert (the key is never loaded — recorded at `SecurityMinimumBar.md:683`) and its non-unix half is already RSA-0002. Shipped NAS unit uses `--at-rest-key-credential`, not the file flag. NAS uid gap is genuinely new and untracked; few-line fix. |
| L4 | Secret-log audit's forbidden-token list omits the identifiers the codebase actually uses, though its doc says it includes them | `rustynetd/src/secret_log_audit.rs:41` | `#![cfg(test)]`, zero live leaks today. But the doc claims a reverse-substring semantic implemented nowhere, and positional args (`error!("{}", x)`) evade every token. Add `passphrase`, `private_key`, `signing_key`, `secret`, `seed` — **not** `key`, which has 20+ benign uses. |
| L5 | `validate_windows_interface_alias` permits PowerShell metacharacters; every value it guards is appended to a `-Command` string | `rustynetd/src/phase10.rs:9102` | **Duplicate of AUDIT-043** (`documents/archive/SecurityAndQualityAudit_2026-06-10.md:430`, open, Low) with the same mechanism and example. Admin-trust-only input; the daemon already runs as SYSTEM, so no boundary is crossed. |
| L6 | Raw-sink ratchet is satisfied by hoisting a `format!` into a local; its 4-line window bleeds onto unrelated lines | `rustynet-cli/…/adapter/validated_args.rs:724` | `#[cfg(test)]`-only, `vm-lab`-gated. Verified: the baseline is 130 and the tree counts 129, so one slot of slack exists; exactly one live bleed site (`linux_traffic.rs:520`) and it is benign (`validate_ip_arg` covers the only interpolated value). Scope the window to the balanced argument list, re-pin to 129. |
| L7 | Backend-boundary gate omits `rustynet-dns-zone` and cannot see a `boringtun` import | `rustynet-cli/src/bin/check_backend_boundary_leakage.rs:10` | The five-path scope is documented and deliberate (`BackendAgilityValidation.md:41`); the dns-zone omission is vacuous today; adding `sysinfo` (which the claim demanded) would red the gate on correct code. Right fix is `deny.toml` entries for `boringtun`/`x25519-dalek` plus a widened pattern with comment handling. |
| L8 | `fetcher::hex_decode` slices a `&str` at a non-char-boundary; the sibling in `ipc.rs` guards exactly this | `rustynetd/src/fetcher.rs:510` | Reproduced (`end byte index 2 is not a char boundary`), and commit `425bb620` added the guard to `ipc.rs` in the same pass while leaving this one. But `fetcher::StateFetcher`/`SignedBundle` have **zero non-test callers** — the daemon drives `daemon::StateFetcher`, whose hex path is byte-based. Dead code; 4-line fix. |
| L9 | NAS `read_sealed_file` bounds-checks the stat but indexes a separately-read buffer | `rustynet-nas/src/store.rs:555` | Stat/read TOCTOU. Not reachable through the tunnel API; the only actor who can win the window is the service uid or root, who already holds the AEAD key. A panic kills one detached session thread, not the daemon. Use `split_at_checked`. |
| L10 | `active_exit` returns `Passed` with the client-egress proof unexecuted when no client node exists | `rustynet-cli/…/stage/active_exit.rs:173` | Half the claimed trigger (missing adapter) is unreachable — adapters are populated for every assignment or the run aborts. Needs a deliberate all-Exit topology no documented invocation produces. Steps 1-2 still ran and fail closed. One `else` arm writing a skip note. |
| L11 | macOS pf-anchor custody test hardens its negatives against self-reference but leaves the positive self-satisfied | `rustynetd/src/macos_exit_killswitch_precedence.rs:539` | The comment three lines below names the trap; the negatives use `format!` assembly, the positive uses a bare literal. No production defect — the audited helper *is* called. The sibling per-line `-f` scan still catches the main regression. One line. |
| L12 | vm-lab feature guard scans `stage/` non-recursively, and the anti-vacuity floor is saturated so it cannot notice | `rustynet-cli/src/vm_lab/mod.rs:38708` | The unscanned `stage/cross_network/scenario/host.rs:212` cargo spawn is production code; simulated the scan and got `checked = 14` against a `>= 12` floor. Dropping `--features vm-lab` there yields exit 101 and a **false red**. The sibling test immediately above already recurses — copy it and raise the floor. |

---

## 3. Systemic patterns

This is where the leverage is. Fixing 28 instances leaves the 29th; these seven rules close whole classes.

### A. Source-text pins that include their own assertion text

**Five confirmed instances**, three of them mutation-proven green with the guarded production line deleted: `linux_killswitch_boot.rs` (×2 tests), `userspace_shared/runtime.rs` + its macOS twin, `macos_exit_killswitch_precedence.rs`, `ops_install_systemd.rs`. Every one uses `include_str!` on the file that contains the test module, so `source.contains("<needle>")` is satisfied by the needle's own string literal.

The repo already has the fix, twice: `windows_install.rs:2101` slices the file at `#[cfg(test)]` and *documents the hazard verbatim* ("a naive `include_str!` would match patterns referenced in the test assertions"), and `rustynet-crypto/src/lib.rs:2323` does the same. This is not an unknown problem; it is a known problem with an established in-repo remedy that four other sites did not adopt.

**Gate that kills the class:** a meta-test that finds every `include_str!` naming its own file and fails unless the result is sliced before the test module — plus a one-time mutation sweep (delete the pinned production line, confirm red) for each existing pin. **Better still, delete the class:** extract argv/rule builders into pure functions (`fn boot_killswitch_rules(iface, port, endpoints) -> Vec<Vec<String>>`) and assert on emitted tokens. A text pin is a test that verifies spelling; the two mutation proofs above show spelling and behaviour diverge silently.

### B. Gates that pass by construction — no failing input exists

Broader than A, and the largest single class here: **10 of 28 findings.** `run_logged_test` (a cargo filter matching nothing exits 0). The vm-lab scan with a floor saturated by files it does scan. `blind_exit`'s non-empty-stdout probe against a command that always prints. `traffic_test_matrix`'s discarded collision flag. `active_exit`'s fallthrough `Passed`. The macOS key-custody stage reporting "5 reviewed artifacts checked" from a keychain-blind set. RSA-0008's gate disabled by the empty directory it always has. The raw-sink baseline with a slot of slack. The Windows fail-closed contract test that is vacuous on Windows. The `linux_fails_closed_when_no_forwarding_rules` test fed an output the real command cannot produce.

The common root is that these gates were written against an *imagined* input rather than a *captured* one. Several of the negative fixtures (`stdout: Vec::new()`, `overall_ok` inconsistency, "0 passed") are shapes the real producer cannot emit.

**Rule:** *every gate must ship with a proven-failing input, and the fixture must come from real producer output.* Concretely — for each `_gates.sh` / `assert_*` / `validate_*` / evidence-writing stage, a negative fixture captured from an actually-broken run, and a CI mutation step that deletes or weakens the guarded line and requires the gate to go red. The anti-vacuity floors that already exist (`checked >= 12`) are themselves an instance of the disease: a floor satisfied with slack detects nothing.

### C. Sibling-platform drift, where the weakest arm is silent

**Seven instances**, always with Linux (the reference) correct and one or both of macOS/Windows quietly weaker: `block_all_egress` (Windows discards, macOS drops the strict flag), `assert_killswitch` (Linux precedence, macOS substring), `apply_nat_forwarding` (Windows drops `blind_exit`), key custody (Linux+Windows assert the passphrase, macOS does not), runtime-ACL evaluator consistency (Windows+macOS cross-check, Linux does not — drift in the other direction), command-runner exit status (Linux checks, Windows does not), `validate_key_custody_permissions` (unix checks owner, Windows does not while claiming parity).

Two mechanisms enable it. First, **an underscore-prefixed trait parameter is a silent contract violation** — `_blind_exit: bool` and `_exit_mode: ExitMode` compile clean and drop a security decision on the floor. Second, **a method absent from one platform's impl is invisible** — nothing flags that `peer_path_sample` is overridden on 2 of N backends, or that `assert_dns_protection` falls to a default on some.

**Gate:** a table-driven cross-platform contract test — one scenario table run against every `DataplaneSystem` / key-custody / command-runner implementation, asserting the *same* outcome shape (fail-closed returns Err; a flag that changes behaviour on one arm changes it on all). Plus a "parity manifest" test that fails when a trait method is overridden on N−1 of N implementations without an explicit documented exemption. And ban `_`-prefixed parameters in `DataplaneSystem` impls by lint: if a platform genuinely cannot honour a flag, it must return `Err`, not ignore it (this is exactly H3's fix).

### D. Dropped `Result`s at security boundaries

`let _ = remove_wfp_tunnel_permit()`, `WireguardCommandOutput` with no status field, `.unwrap_or_default()` on a privileged query. The problem is not the pattern — some of these ignores are *correct* (`netsh delete` of a rule that legitimately does not exist). The problem is that a correct ignore and a bug are spelled identically.

**Gate:** `#![deny(let_underscore_must_use)]` at the crate root for `rustynetd` and the backend crates, with `#[allow]` + a one-line comment required at each genuinely-idempotent site. That turns "ignored because absence is success" from an implication into a written claim a reviewer can check. Verification for M2 shows why this matters: a naive `?` on all three Windows calls would have been *worse* than the bug.

### E. Controls with an enforcement point and no reachable execution

RSA-0008's membership directory (zero non-test installers). `peer_path_sample` (implemented on two backends, dispatched by none). `evaluate_macos_killswitch_rules` (wired only into an offline report binary). `ValidatedArg::ConnectionUser` (constructed nowhere — refuted as a *defect* because the trust boundary validates upstream, but the same shape). The macOS keychain probe (never written). Every one of these satisfies CLAUDE.md §4's "enforcement point + verification method" on paper.

Compounding it: **ledger entries marked DONE by commits that never touched the named file.** PF-05 is recorded closed at `8417edf1`; that commit touched neither `phase10.rs` nor any daemon call site, and the finding's own text names `phase10.rs`. Three of the four S2 sibling sites got real fixes; the fourth got a ledger tick.

**Gate:** two cheap checks. (1) A reachability test: every function named in `SecurityMinimumBar.md` or a remediation ledger must have a non-test caller — fail the build otherwise. (2) A ledger discipline rule enforced in CI: a remediation entry cannot be marked DONE unless `git show --stat <cited-commit>` includes the file the finding names.

### F. Denylists where §10.4 requires default-deny

The Windows SDDL check (three forbidden principals, everything else allowed). The secret-log forbidden-token list (nine names, none of them the ones in use). `validate_windows_interface_alias` (rejects five things, admits `;` `$` `` ` `` `|` `&`). Each fails open on the input it did not anticipate — which is the only input that matters for a validator.

CLAUDE.md §10.4 mandates default-deny for "ACL, routes, and trust-sensitive flows". **Extend it explicitly to validators and scanners:** every input validator must be an allowlist over a proven-safe alphabet or principal set, never a denylist. Cross-platform, the same field already demonstrates the right answer — `macos_exit_nat.rs:200` accepts `[A-Za-z0-9._-]` and nothing else.

### G. Validate the summary, then use the data

`overall_ok` trusted while the per-root statuses say otherwise. `metadata.len()` bounds-checked, then a separately-read buffer indexed. `has_collision` computed, then the colliding map committed anyway. Same rule in all three: **validate the artifact you actually consume, at the moment you consume it.** A stat is a pre-filter, never an authority for an index; a summary flag is a hint, never a substitute for the rows it summarises.

### H. Evidence written only on failure

`traffic_test_matrix`, `active_exit` and several sibling stages write their artifact only in the failure arm. A green stage therefore records a verdict with none of the data behind it — which is precisely how the 35 permanently-contaminated `two_hop` rows the repo already tracks as QH-07 came to exist.

**Rule:** a stage that records a pass must write the evidence artifact containing the data behind the verdict *on the pass path*. A stage with no evidence file is `NotProven`, not `Passed`. This one rule would have caught H4, M9, L10 and the QH-07 contamination class at the point of writing rather than months later.

---

## 4. What I would fix first

Ordered for long-term security, not speed.

**1. The class-level gates in §3.A and §3.B — before any individual instance.** Two mutation-proven tests in this review were green with the code they guard deleted. Until a CI step deletes a guarded line and requires red, you do not know which of the remaining pins are real, and every new pin written this quarter inherits the defect. This is a day of work that converts an unknown number of vacuous tests into a known number. Do this first because it is the only item that gets *cheaper* to fix the earlier you do it — every subsequent fix in this report lands with a verifiable test instead of a hopeful one.

**2. H1, the membership owner-signer gap — as an owner decision, not an agent fix.** It is the one finding that touches the actual root of trust, and the naive fix (add both arms to `matches!`) makes every enrollment owner-signed, which the gossip handoff doc explicitly warns against. Decide the split (owner-free `AddNode` restricted to exactly `{Client}`; owner required for privileged capabilities or for reusing a removed `node_id`), then implement. The reproduction harness is in the verification record; write it as a permanent negative test.

**3. H2, the Windows exit-status blindness.** One struct field and one `map_err`, but it un-blinds the entire Windows backend — peer removal, allowed-ips narrowing, route programming, exit-mode transitions. Windows is the platform furthest from parity, and every future Windows lab run is currently interpreting silence as success. Fixing this makes the next Windows debugging session possible rather than merely faster. Handle the idempotent-delete cases explicitly.

**4. H3 + H4 together — the two "green because it is wrong" defects.** H3: return `Err` for `blind_exit` on Windows and add `ValidateSet` to the installer parameter; that is an hour, and it protects an irreversible role from a silent downgrade that the assertion then blesses. H4: fail the stage on a mesh-IP collision and refuse self-pings; that is twenty lines, and it protects the ledger the release reads.

**5. Then the parity table test (§3.C) and the `let_underscore_must_use` deny (§3.D).** These close M2, M3, M7 and L2 as a group, and prevent the next `_blind_exit` from compiling.

Everything else is a queue item. Note that four findings are duplicates of already-open ledger entries (M4 = RSA-0008, L5 = AUDIT-043, L2 = F2.b, part of L3 = RSA-0002) — those need a disposition decision more than they need code.

**One thing to fix that is not a code change:** the PF-05 ledger entry. A remediation record that marks a finding DONE against a commit that never touched the file is worse than an open finding, because it removes the item from every future search. Audit the S2 set for others of the same shape.

---

## 5. Coverage — honest note

**All ten dimensions produced surviving findings.** Nothing came back empty, so there is no area this review can certify as clean by silence. Distribution: crypto-custody 5, test-integrity 5, backend-boundary 4, daemon-failclosed 3 (2 after merge), lab-validators 3, policy-acl 2, platform-parity 2 (1 after merge), panics 2, privileged-exec 2, trust-state 1.

**What this review could not reach, and should not be read as clearing:**

- **Anything requiring execution.** Every finding here is static. No live-lab run, no Windows or macOS node was driven, no fuzz target was run beyond confirming it compiles. H2 and H3 are Windows-runtime defects found by reading; their *absence* elsewhere on Windows is unproven. The macOS and Windows arms in general got less effective scrutiny than Linux simply because Linux is where the reference implementation and the test coverage are.
- **Cryptographic protocol correctness.** The custody dimension checked *where keys live and who can read them*. It did not analyse the gossip trust model, the enrollment token protocol, replay-watermark semantics, or the signed-bundle epoch algebra. H1 surfaced a membership-authority hole by inspection, not by systematic protocol review — that is a gap, and the trust-state dimension is the one I would run again at depth.
- **Supply chain.** `cargo audit` / `cargo deny` were not run as part of this review, and `deny.toml`'s coverage was only examined incidentally (it bans weak-crypto crates and nothing structural about backend boundaries).
- **The workspace-excluded crates.** `gui/` was not looked at at all — CLAUDE.md §7 already notes it is unwired from every gate. `rustynet-lab-monitor` and `fuzz/` were touched only where a finding crossed into them.
- **Concurrency and resource exhaustion.** No dimension covered races beyond the two TOCTOU instances found incidentally (L9, and the stat/read shape in §3.G), and none covered DoS, memory growth, or the relay data path under load.

**Two calibration notes on the findings that did survive.** First, 12 of 41 claims (29%) were refuted, and the refutations follow one pattern: reviewers traced a code path and asserted reachability without checking the installer, the startup preflight, or the stage dependency graph. Treat any future finding that does not explicitly state *how the input gets there* as unverified. Second, the corrected-severity column moved down in 20 of 28 surviving cases and up in one; the filing agents' severity judgements were systematically inflated, and the verification pass is what made this list usable. Read the low tier as genuinely low.

**The clearest signal in the coverage itself:** this review found more defects in the machinery that verifies the code (8 in test-integrity and lab-validators, plus M8) than in the trust-state and policy paths combined (3). The production security core held up under attack. The evidence about it did not.
