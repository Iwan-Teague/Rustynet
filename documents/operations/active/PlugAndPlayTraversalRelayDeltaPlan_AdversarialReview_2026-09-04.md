# PlugAndPlayTraversalRelayDeltaPlan (2026-03-29) — Adversarial Review

**Status: UNTRUSTED — AI-generated adversarial review, 2026-09-04, worktree commit `e40cceb01d46b2cfabbb405a44e756f658d38e3e` (branch `ai-edit/edit-1788550059312-26537-16`).** Every claim below was checked against the actual tree by reading files and grepping symbols; commit SHAs were verified with `git cat-file -t` and `git merge-base --is-ancestor`. This review is not itself source-of-truth guidance; the reviewed plan and the active ledgers remain authoritative. Line numbers cited here are valid at the review commit and will drift.

## Scope and method

The review target is `PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md` (4,275 lines, read in full). That plan carries a HISTORICAL banner (2026-08-19) stating its defect sections were largely closed by the D2–D4 tracks of `RustynetDataplaneExecutionPlan_2026-05-18.md`; this review verifies that claim symbol by symbol, flags what has gone stale since, and confirms no shipped control depends on a weaker behavior than the plan specified. Checks were performed directly against the worktree: `rg` for every symbol and test name the plan cites, `sed -n` reads at the cited lines, and git plumbing for the four commit SHAs the plan embeds.

## Verdict

**The plan's defect inventory (§8) is genuinely closed in code — every defect it names has a shipped, tested fix at this commit — but the document's line-level citations, two symbol names, and its macOS backend status claims have drifted badly; it should stay active-with-banner (not archived) because its unfinished Phase C/D/E live-evidence gaps are still referenced by other active ledgers.** No fix it shipped weakens a fail-closed control.

---

## Findings

Severity scale: `none` (verified correct / DONE), `info` (cosmetic drift), `medium` (misleading but non-security), `high` (would misdirect future work or misstate a control).

### F1 — §8.1 STUN candidate-port guessing: RESOLVED (DONE)

Claim: guessed ports replaced by typed `StunResult { mapped_endpoint, server, local_addr }`, `gather_mapped_endpoints_with_round_trip`, deleted `gather_public_ips()`, plus integration tests.

Tree reality:
- `gather_public_ips` is absent from `crates/rustynetd/src/stun_client.rs` (deleted, as claimed).
- `StunResult` at `stun_client.rs:271`; `gather_mapped_endpoints` at `:320`; `gather_mapped_endpoints_with_round_trip` at `:402`.
- Tests `d2_stun_v4_discovered_port_equals_bound_socket_port` (`:1316`) and `d2_stun_v6_discovered_port_equals_bound_socket_port` (`:1352`) exist and bind a real socket, then assert the discovered mapped port equals the bound port — the exact regression the defect described.
- Companion tests also present: `test_gather_mapped_endpoints_uses_provided_socket_identity` (`:841`) and, in `crates/rustynetd/src/daemon.rs`, `stun_local_port_match_state_reports_mismatch_when_observed_port_differs` (`:20489`, helper fn `:3254`).

Severity: **none — DONE** (one naming drift, see F13).

### F2 — §8.2 relay client side-socket: RESOLVED (DONE)

Claim (original defect): `load_relay_client(...)` bound a separate ephemeral UDP socket despite the client's own doc comment saying the socket should be shared with WireGuard.

Tree reality:
- `load_relay_client` at `daemon.rs:4975` contains **no** `UdpSocket::bind` — it constructs via `RelayClient::new_with_token_issuer` and fails closed when an incompatible configuration combination (persisted-token spool together with local signing) is requested.
- `crates/rustynetd/src/relay_client.rs:55-60`: the `local_port_hint` doc explicitly states the optional side socket must not be treated as the authoritative transport.
- `RelayClient::is_bound()` at `:421`; session map is one slot per peer (`HashMap<NodeId, RelayClientSession>`, `:332`).
- The plan's own §18.2 correction ("daemon.rs no longer binds the relay client on a separate socket") is confirmed.

Severity: **none — DONE**. Fail-closed posture intact.

### F3 — §8.3 relay daemon placeholder: RESOLVED (DONE)

Claim (original defect): `rustynet-relay/src/main.rs` was a 33-line placeholder.

Tree reality: `main.rs` is now **6,435 lines**. All the implementation the plan's Phase C claims is present:
- `RelayConfig` (`:149`), default control bind `0.0.0.0:4500` (`:193`, `:3083`), forwarded-port range 50000–59999 (`:3087`), tokio `ctrl_c` shutdown (`:833`).
- Wire functions: `parse_relay_hello` (`:1532`), `parse_relay_token` (`:1616`), `serialize_relay_hello_ack` (`:1755`), `serialize_relay_reject` (`:1764`); session cleanup and per-port forward tasks present.
- `crates/rustynet-relay/Cargo.toml`: `daemon` feature (`:47`), optional `tokio` (`:21`), `sha2` (`:18`), `required-features = ["daemon"]` (`:51`) — matching the plan's feature-gating plan.
- The codebase has moved past the plan: files the plan never envisioned exist (`session.rs` with `RelaySession` at `:64`, `blind_relay_listener.rs`, `rate_limit.rs`, `hello_limiter_audit.rs`).

Severity: **info** — the plan's "~550 line" implementation figure is far behind reality (it was 3,848 lines by the July 2026 `DocCodeDiscrepancyAudit` DA-19 entry; 6,435 now). The direction of drift is strictly more implementation, not less.

### F4 — §8.4 relay-active runtime honesty: TIGHTENED (DONE)

Claim: `relay_active` originally reachable without proof; plan tightened it.

Tree reality: `daemon.rs:8525` — the `relay_active` reason string is now `relay_selected_endpoint_with_fresh_handshake`, i.e. liveness requires the selected relay endpoint to match an authenticated session **and** a fresh handshake. `relay_session_disabled` (`:8533`) is now only a `live_reason` label when relay peers are programmed but no session is configured — an explicit operator-disabled state, exactly the §10.4 intent. Guarding tests exist: `daemon_runtime_relay_session_becomes_live_only_with_selected_endpoint_and_fresh_handshake` (`:29031`) and `daemon_runtime_relay_session_endpoint_mismatch_is_not_live` (`:29091`).

Severity: **none — DONE**.

### F5 — §8.5 relay demux / allocated-port contract: RESOLVED (DONE)

Claim: allocated-port attribution made single-authority in `RelayTransport`; unauthorized keepalives rejected; expiry enforced.

Tree reality: `forward_packet` at `crates/rustynet-relay/src/transport.rs:626`; tests `test_keepalive_rejects_unbound_and_wrong_tuple_activity` (`:2319` — unbound keepalive ignored, wrong-tuple keepalive rejected) and `forward_packet_rejects_at_exact_expiry_second` (`:3182`) confirm the contract. The plan's v1 design (allocated UDP port attribution, **no** per-packet outer framing, §9.4 `:445-449`) is what the code actually implements.

Severity: **none — DONE**.

### F6 — Phase A transport-socket-identity blocker: RESOLVED for userspace-shared backends, but plan's macOS claims now STALE

Verified intact:
- Trait surface in `crates/rustynet-backend-api/src/lib.rs`: `authoritative_transport_identity` (`:302`), `authoritative_transport_round_trip` (`:308`), `transport_socket_identity_blocker` (`:353`).
- `LinuxUserspaceSharedBackend` (`crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs:33`, `impl TunnelBackend :429`, `authoritative_transport_identity :560`, `authoritative_transport_round_trip :567`) — symbols real; the plan's line cites (`472-476`, `478-486`) have drifted.
- Kernel/command backends still correctly report `Some(blocker)`: `macos_command.rs:693-696`, `linux_command.rs:544-547`, `windows_command.rs:567` — **fail-closed preserved** where no shared socket exists.
- `crates/rustynetd/src/main.rs:3684-3701` now accepts the `linux-wireguard-userspace-shared` / `macos-wireguard-userspace-shared` backend names (the plan's 2026-03-31 "daemon rejects them" note is historical only).

Stale claim (**medium**): the plan states repeatedly (`:2089`, `:2159`, `:2266`, `:3001`) that macOS userspace-shared parity is out of scope / blocked / "Phase 1 scaffolding only". At this commit `MacosUserspaceSharedBackend` **exists**: `crates/rustynet-backend-wireguard/src/userspace_shared_macos/mod.rs:32`, `impl TunnelBackend :513`, `authoritative_transport_identity :650`, `authoritative_transport_round_trip :657`. Anyone relying on the plan's macOS status would understate the current code. The controlling status source is `CrossPlatformRoleParityRefresh_2026-07-23.md`, not this plan.

### F7 — Named test inventory: all present (DONE), line cites drifted

All 14 daemon-runtime tests the plan names exist (current `daemon.rs` lines): `traversal_bundle_set_accepts_signed_coordination_and_rejects_malformed_section :26863`; `daemon_runtime_transport_socket_identity_blocker_fail_closes_relay_bootstrap :27909` (now with a newer sibling `..._rejects_bound_relay_side_socket :27964`); `daemon_runtime_linux_userspace_shared_backend_reports_authoritative_transport_state :28043`; `daemon_runtime_authoritative_stun_refresh_uses_backend_shared_transport_identity :28370`; `daemon_runtime_relay_keepalive_failure_reestablishes_once_on_authoritative_transport :28769`; `daemon_runtime_relay_keepalive_reestablish_failure_fail_closes :28859`; `daemon_runtime_peer_removal_tears_down_associated_relay_session :28926`; `daemon_runtime_relay_session_becomes_live_only_with_selected_endpoint_and_fresh_handshake :29031`; `daemon_runtime_relay_session_endpoint_mismatch_is_not_live :29091`; `daemon_runtime_requires_signed_coordination_for_direct_probe_attempts :29261`; `daemon_runtime_auto_tunnel_periodic_reprobe_recovers_direct_after_relay :29552`; `daemon_runtime_auto_tunnel_direct_health_uses_live_handshake_without_forced_reprobe :29887`; `daemon_runtime_auto_tunnel_direct_liveness_expiry_falls_back_to_relay :30045`; `daemon_runtime_auto_tunnel_traversal_probe_recovers_direct_when_handshake_arrives :30200`.

Traversal roam tests in `traversal.rs` exist at `:2215`, `:2236`, `:2260`, `:2284` — the plan claims three; there are **four** (an extra multi-step-roam case the plan undercounts). The daemon endpoint-change tests exist (`:30960`, `:31074`, `:31183`), though the plan's description "debounced within stability window" does not match any test name verbatim — the closest are the idempotent-fingerprint and fingerprint-memo-invalidation tests.

Severity: **info** — inventory correct; the plan's own "signed coordination replaces fabricated zeroed schedule" claim is confirmed by `evaluate_traversal_probes` (`phase10.rs:8192`) taking `coordination_schedule: Option<...>` (`:344`) — the schedule is signed input, never fabricated.

### F8 — §10 file-by-file citations: symbols real, line numbers drifted

Everything the plan cites exists, at different lines (files have grown enormously; `daemon.rs` is >31k lines):
- `poll_stun_results` now `daemon.rs:6972` (plan said 3750-3779), calling `authoritative_transport_round_trip` at `:6998`.
- `DaemonBackend::authoritative_transport_round_trip` now `:4324-4351` (plan said 2376-2378); blocker capture `:5158-5161` (plan said 2789-2791).
- `stun_candidate_local_addrs` `:7019`, `stun_transport_port_binding` `:7023`; netcheck diagnostics include `transport_socket_identity_state`/`transport_socket_identity_error` (`:7322`).
- `handshake_is_fresh` at `traversal.rs:1887` and `phase10.rs:8547`; `execute_simultaneous_open` `traversal.rs:1514`; `SimultaneousOpenRuntime` `traversal.rs:724`; `reconfigure_managed_peer` `phase10.rs:8488`.
- `apply_rollback_forces_fail_closed_when_system_step_fails` `phase10.rs:15273`; `persist_waits_for_brief_lock_contention` `resilience.rs:773` with the deadline-based wait window `:298-373`.

Severity: **info** — expected drift for a frozen document; recorded here so future readers re-grep instead of trusting the plan's numbers.

### F9 — Control-crate surface: verified (DONE)

`crates/rustynet-control/src/lib.rs`: `derive_endpoint_hint_signing_key :3606` (test at `:8358`), `RelaySessionToken :1756`, `RelaySessionTokenRequest :1769`, `EndpointHintCandidateType :1476`, `SignedEndpointHintBundle :1511`, `RelayFleetNodeDescriptor :1521`, `SignedRelayFleetBundle :1539`. The §6.1 "existing capabilities" list is accurate.

Severity: **none — DONE**.

### F10 — CI gates and report validators: verified (DONE)

All named gate scripts exist in `scripts/ci/`: `phase10_gates.sh`, `phase10_cross_network_exit_gates.sh`, `phase10_hp2_gates.sh`, `membership_gates.sh`, plus `check_phase10_readiness.sh`, `fresh_install_os_matrix_release_gate.sh`, `check_fresh_install_os_matrix_readiness.sh`. In `crates/rustynet-cli/src/ops_cross_network_reports.rs` the six canonical report filenames are pinned (`:35`, `:57`, `:80`, `:112`, `:141`, `:167`) and the three named validators exist: `validate_cross_network_remote_exit_readiness_accepts_complete_canonical_reports :3389`, `validate_report_payload_rejects_failback_pass_without_measured_child_artifacts :3521`, `validate_report_payload_rejects_pass_status_with_critical_path_alarm :3716` — fail-closed pass-gating on measured evidence, as the plan claims.

Severity: **none — DONE**.

### F11 — §12E "live scripts require `rustynet netcheck` live path proof": UNVERIFIABLE against its named scripts (**medium**)

The six scripts the plan names (`live_linux_cross_network_{direct_remote_exit,relay_remote_exit,failback_roaming,remote_exit_dns,remote_exit_soak,traversal_adversarial}_test.sh`) **do not exist** in `scripts/e2e/` — the only `cross_network` match there is `apply_cross_network_impairment_profile.sh`. Successor scripts exist (`live_linux_relay_test.sh`, `live_linux_two_hop_test.sh`, `live_linux_path_handoff_under_load_test.sh`, …), but none of them reference `netcheck` or `path_live_proven` at all. The plan's checked box therefore cannot be confirmed on its own named artifacts; the netcheck/path-live-proven enforcement that does exist is in the `ops_cross_network_reports.rs` validators (F10) and the orchestrator's live stages, not in shell scripts. A reader looking for the claimed script-level enforcement will not find it. This is a documentation-accuracy gap, not a control gap: nothing in the tree passes a gate without measured evidence.

### F12 — Artifact-status claims are environment-local history, unverifiable from the repo (**info**)

`artifacts/` is not tracked in git (only `.gitkeep` files; `artifacts/phase10/` is empty in this worktree). The plan's claims about `fresh_install_os_matrix_report.json` being refreshed to `1a94de1`, the six canonical cross-network reports being absent, and `traversal_path_selection_report.json` / `traversal_probe_security_report.json` describe a particular machine's state on particular dates. They cannot be re-verified from the repository and should be read as dated lab history. The four commit SHAs the plan embeds, however, are all real and all ancestors of HEAD: `06e3e2ed745b…` (2026-03-30), `c86a62a766b8…` (2026-03-26), `425faa411ce7…` (2026-05-14), `1a94de1` (2026-05-09) — dates match the plan's claims.

### F13 — Two stale symbol names (**info**)

- `query_stun_server_full()` (plan §18.2) is now `query_stun_server_with_socket` (`stun_client.rs:458`).
- The plan's §6.1 name `query_stun_server()` for the deleted internal matches the *pre-fix* code; the replacement is as above.

### F14 — Dead cross-reference (**info**)

The plan links `CrossNetworkRemoteExitNodePlan_2026-03-16.md` under `documents/operations/active/`; that file now lives in `documents/archive/`. Update or annotate the link.

### F15 — Supply-chain residue from the 2026-04 Phase 7 entry: resolved (**info**)

The plan's Phase 7 evidence records `cargo audit` failing on `paste 1.0.15` (RUSTSEC-2024-0436, via tun-rs → route_manager → netconfig-rs → netlink-packet-core) plus license failures. At this commit `paste` is absent from `Cargo.lock` entirely, as are `ip_network`, `ip_network_table`, and `libloading`; `ring` and `untrusted` remain present as license-tracked dependencies, which is expected. The exposure the entry describes is gone.

## Verified-correct (spot-check list)

Everything below was confirmed in-tree at the review commit:

1. STUN mapped-endpoint pipeline with caller-provided sockets, IPv6 parity tests, and port-match diagnostics (F1).
2. Relay client boot with no self-bound authoritative socket and fail-closed config validation (F2).
3. Full relay daemon: config parsing, control port 4500, 50000–59999 forwarding, hello/token/ack/reject wire functions, graceful shutdown, feature gating (F3).
4. `relay_active` gated on selected-endpoint match + fresh handshake; `relay_session_disabled` as opt-in operator state only (F4).
5. Allocated-port tuple attribution as single authority in `RelayTransport`, with unauthorized-keepalive and exact-expiry rejection tests (F5).
6. Backend trait `transport_socket_identity_blocker` failing closed on kernel/command backends on all three desktop platforms (F6).
7. Signed coordination schedules as a precondition for simultaneous-open probes, with adversarial tests (F7).
8. The complete named-test inventory across `daemon.rs`, `traversal.rs`, `phase10.rs`, `resilience.rs` (F7, F8).
9. Control-crate signed-bundle/token surface (F9).
10. CI gate scripts and the six canonical cross-network report validators with fail-closed pass conditions (F10).
11. All four embedded commit SHAs real and ancestral, with matching dates (F12).

## Considered, no issue

- **§9.4 relay model vs. shipped code**: the plan's v1 decision — relay is not an exit, forwards ciphertext only, token-scoped, rate-limited, attributed by allocated UDP port with **no per-packet outer framing** (`:445-449`) — is exactly what `transport.rs` implements. A later proposal document cites this section as a shipped invariant; the citation remains valid.
- **Fail-closed posture**: no verified fix weakens any control. The socket-identity blocker still trips on every backend lacking a shared socket; relay liveness still demands fresh handshakes and endpoint matches; report validators still refuse pass status on missing measured artifacts; the relay client still refuses incompatible key-custody configurations at load.
- **The HISTORICAL banner itself**: accurate. The plan's defect sections *are* closed by the D2–D4 work; the banner's suppression of the §3 status matrix in favor of `CrossPlatformRoleParityRefresh_2026-07-23.md` is the correct precedence.
- **Plan's self-assessed incompleteness (§18.3)**: honest. Its own Definition of Done (§19) requires live cross-network evidence that its named artifacts never delivered, and the doc says so. The later `two_hop` history should be read from the per-stage ledger (`documents/operations/live_lab_node_stage_results.csv`), never from the contaminated `linux_stage_two_hop` run-matrix column (AGENTS.md §12.3).

## Recommended disposition

**Keep the plan in `documents/operations/active/` with its HISTORICAL banner; do not archive to `operations/done/` yet.** Rationale: although every §8 defect is code-closed, the plan is the design record for the traversal/relay path state machine (§9.2) and relay model (§9.4) that other active ledgers (`Phase4LiveLabEvidenceRefreshChecklist_2026-04-12.md`, `WindowsExitAndRelayDeltaPlan_2026-05-10.md`) still reference for the unfinished Phase C/D/E live-evidence work. Archive it only when those ledgers stop citing it or the live cross-network evidence lands. Corrections this review warrants (apply opportunistically, low urgency given the banner): the F6 macOS status claims, the F11 live-script claim, the F13 symbol names, and the F14 dead link.
