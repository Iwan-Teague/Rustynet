# Cross-Platform Role Parity Plan — 2026-06-21

> **READ THIS IF YOU ARE ASSESSING PROJECT COMPLETENESS.** This document is the
> single source of truth for the requirement that **every Rustynet node role and
> capability must work — and be live-lab-proven — on Linux, macOS, AND Windows.**
> It consolidates a requirement that was previously scattered across several
> delta plans so it cannot be missed.

## 1. Mandate (non-negotiable completeness criterion / release blocker)

Rustynet **cannot be called complete** until a user can run it on whatever
computer they have — Linux, macOS, or Windows — and operate that node as **any**
role with no OS being a capability limiter:

> client · admin · anchor · exit · blind_exit · relay · (service-hosting: nas · llm)

**Linux is the reference platform and has full role parity, proven live.**
**macOS and Windows do NOT yet.** Closing that gap — every role, every
capability, every constraint/config/variable, proven live in the UTM lab on both
macOS and Windows — is a **release blocker**. Security is never traded for parity:
each role's platform-native dataplane must preserve fail-closed, default-deny,
kill-switch, DNS-fail-closed, signed-state verification, and anti-replay exactly
as Linux does.

## 2. What "parity" means per role (must hold on macOS AND Windows)

For each role, the node must do, **live**, everything Linux does:
- **client** — enroll, ingest signed membership/assignment/traversal/dns, bring up
  the WireGuard tunnel, route through its assigned exit, kill-switch + DNS
  fail-closed in protected mode.
- **admin** — hold signing authority; mint/issue + distribute signed membership
  and assignment bundles to peers; append-only role audit.
- **anchor** — serve the anchor capabilities live: `gossip_seed`, `bundle_pull`,
  `enrollment_endpoint`, `relay_colocation`, `port_mapping_authoritative`.
- **exit** — NAT/masquerade peer egress to the internet with the platform-native
  dataplane (Linux nftables, macOS `pf`, Windows WinNAT/WFP), advertise the
  default route, enforce the exit kill-switch + DNS leak prevention.
- **blind_exit** — the irreversible exit variant (destructive transition;
  factory-reset-only exit path) with the same dataplane + the immutability gate.
- **relay** — run the relay service and forward live sessions for peers that
  cannot hole-punch.
- **service-hosting (nas, llm)** — tracked under the D13 program (see
  `ServiceHostingRolesRoadmap_2026-06-11.md`); parity for these is in-scope for
  completeness too once their base roles land.

Plus **live role transitions** between these roles on each OS (Linux launchd/
systemd ✓; macOS launchd + Windows windows_service — see §6).

## 3. LIVE-PROVEN status matrix (code-present ≠ proven)

Legend: ✅ live-proven · 🟡 implemented, not yet run green live · 🟠 contract/dry-run
validator only (no live runtime) · ❌ untested / not implemented · 🔒 blocked.

| Role / capability | Linux | macOS | Windows |
|---|---|---|---|
| client (tunnel + route through exit) | ✅ | ✅ (mac2, 2026-06-21: ExitActive, live handshake) | ✅ join+security proven (win3); active client traffic pending cross-OS run |
| admin (mint/issue signed bundles) | ✅ | ✅ **live-proven 2026-06-22** (`validate_macos_admin_issue` stage, run `livelab-1782135034`): the macOS node mints its own assignment signing authority (`assignment init-signing-secret`) + issues a valid signed assignment bundle (`assignment issue`, 447 bytes) on the guest; `--admin-platform macos` selector + `is_macos_active_admin` gate + FAIL-LOUD stage. The earlier "self-mint deliberately disabled" note was unbacked by code. | ✅ **live-proven 2026-06-27** (`validate_windows_admin_issue` stage PASS, run `livelab-1782526081`): the Windows node mints its own DPAPI-custodied signing authority (`trust keygen`) and issues a signed trust bundle (`trust issue`, 286 bytes + 65-byte verifier key) on the guest — the Windows analogue of the macOS assignment-issue path, via the platform-native DPAPI trust CLI. The installed `rustynet.exe` IS the trust-only CLI; the unix `assignment init-signing-secret`/`issue` verbs (encrypted-at-rest file key custody) do not exist on Windows, so admin authority is proven through `trust keygen`+`trust issue`. `--admin-platform windows` selector + FAIL-LOUD stage; `validate_windows_mesh_join` PASS. Fixed in `afd011e` (the prior helper called the nonexistent `assignment` verbs → `bad_args: usage: rustynet trust`). |
| anchor (gossip/bundle-pull/enrollment/port-map) | ✅ | ✅ **bundle-pull LIVE-PROVEN 2026-06-22** (run `live-lab-anchor-fix2`, `validate_macos_anchor_bundle_pull` PASS): implemented end-to-end (launchd `com.rustynet.anchor.plist` loopback bundle-pull profile + `ops install-macos-anchor` verify-before-serve installer + `macos_service_hardening` reviewed-shape validator + `ops e2e-bootstrap-macos` seeds the bundle-pull token + live `live_macos_anchor_test` bin asserting loopback byte-for-byte / token gate / LAN-bind refused / secrets hygiene, wired into the `validate_macos_anchor_bundle_pull` vm_lab stage, FAIL-LOUD: the live result is authoritative and the dry-run plan is informational-only, never a Pass) — **deploy + listener live-proven**: `deploy_macos_anchor_profile` now DERIVES the anchor launchd profile from the proven `com.rustynet.daemon.plist` (inheriting its node-specific keychain account + `/bootstrap/` passphrase custody + state paths) and adds ONLY the bundle-pull listener (verify-before-serve loopback + allow-lan=false asserted in-stage); `amend_membership_for_macos` grants `anchor.bundle_pull` when elected; `ops seed-macos-anchor-token` chowns the token to the `rustynetd` daemon user. This fixed three layered crash-loop bugs found via the focused-loop on .210 (generic keychain account `wg-passphrase-daemon-local` → node-specific from the client plist; static-plist state-path divergence → derive-from-client; root-owned token → chown). Listener binds `127.0.0.1:51822` and the live test passes loopback byte-for-byte + token gate + LAN refused + secrets hygiene. (Known follow-up: `cleanup_hosts` must bootout `com.rustynet.anchor` between runs.) gossip/enrollment/port-map still via the shared `live_linux_anchor_test --platform macos` path | ✅ **bundle-pull LIVE-PROVEN 2026-07-03** (run `labrun-1783079551578-32671-0`, commit `786f900`, `validate_windows_anchor_bundle_pull` PASS): deployed the Windows anchor service on `windows-utm-1`, initialized a self-contained genesis snapshot where the node holds `anchor.bundle_pull`, bound a verify-before-serve loopback listener on `127.0.0.1:51822` with `allow_lan=false`, locked the token ACL, and passed loopback byte-for-byte / token gate / LAN-refused / secrets-hygiene assertions. Same run proved the two immediately preceding Windows audit blockers fixed: `validate_windows_enrollment_replay` PASS after treating Windows lock-file `PermissionDenied` as bounded contention, and `validate_windows_hello_limiter_flood` PASS after Windows bootstrap built, installed, and signed `rustynet-relay.exe`. Remaining anchor scope beyond bundle-pull (gossip/enrollment_endpoint/port-map) stays tracked separately. |
| exit (NAT egress + route advertise + killswitch) | ✅ (nftables) | ✅ **LIVE-PROVEN 2026-07-03** (run `labrun-1783087254263-11121-0`, commit `039f215`, `--macos-promote-exit`): `activate_macos_exit_role`, `capture_macos_exit_evidence_artifacts`, `validate_macos_exit_nat_lifecycle`, `validate_macos_exit_dns_failclosed`, `validate_macos_service_hardening`, and `validate_macos_mesh_status` all passed; `partial` was selector/optional skips only. | 🟡 implemented (`promote_windows_exit_active`, `validate_windows_exit_nat_lifecycle`) but 🔒 the lab Windows guest lacks the WinNAT/HNS stack (`MSFT_NetNat` absent) — see `WindowsExitNodeRunbook_2026-06-04.md` |
| blind_exit (irreversible exit) | ✅ | ✅ **live-proven 2026-06-29** (orchestrate stage, run `labrun-1782770042330-16244-0`, commit `ed3ed7e`, `--blind-exit-platform macos`): `validate_macos_blind_exit` PASS — irreversible transition applied on macos-utm-1, pf anchor `com.rustynet/blind_exit` loaded (9 rules, no route-to/reply-to/dup-to), immutability gate enforced. Runtime: `macos_blind_exit.rs` pf builder/evaluator + daemon invariants + the mesh-egress-source CIDR bound from the pfctl-boundary review. Stage drives `role set blind_exit --accept-irreversible`, asserts pf anchor hardened, verifies immutability gate blocks leaving. Fixed in `5386c09` (blind_exit via plist rewrite + daemon restart instead of blocked `role set`) and `ed3ed7e` (allow pf anchor load with stale client membership). | 🚫 **out of scope by design** — `main.rs:11833` hard-errors "blind_exit role is supported on Linux/macOS only"; like mobile clients, not a parity gap (corrected 2026-06-24, was ❌) |
| relay (live session forwarding) | ✅ | ✅ **lifecycle LIVE-PROVEN 2026-06-27** (orchestrate stage, run `livelab-1782571161`, commit `cd6a834`, `--relay-platform macos`): `validate_macos_relay_service_lifecycle` PASS — install/bootstrap → active (`/healthz` ok, `127.0.0.1:4501` bound) → stop/release (released after stop). The loopback `/healthz` wedge that blocked this was fixed by `574eaac` (the macOS PF killswitch now emits `pass quick on lo0 all` — previously it wedged loopback TCP, SYN_RCVD on `127.0.0.1:4501` → empty `/healthz`; verified in the live render path `render_macos_killswitch_pf_rules` phase10.rs, scoped to lo0 before the terminal `block drop out quick all`, at parity with the Linux killswitch's `oifname "lo" accept`). Earlier focused-proof on .210 2026-06-22 (`356f8a3`): `install-macos-relay` → relay `state=running`, `127.0.0.1:4501` bound, `/healthz={"status":"ok",...}` → `--uninstall` → released. Live cell `exercise_macos_relay_lifecycle_live` fixed (upload the static reviewed `com.rustynet.relay.plist` + run from a temp cwd since the bootstrap build dir is ephemeral; derive `--verifier-key` from the distributed trust verifier `trust-evidence.pub` written root-owned via `tee`, since `assignment.pub` is not distributed to macOS). **Live session forwarding remains HP-3-gated** (no live forwarding proven on ANY OS yet — the same cross-OS gate as the Linux ✅; macOS relay is now at lifecycle parity with Linux). | 🟠 SCM lifecycle **contract** only (`validate_windows_relay_service_lifecycle_contract`, "without guest mutation") — no live forwarding |
| live role transitions (cross-OS) | ✅ (`role_switch_matrix`) | ✅ **LIVE-PROVEN 2026-07-04** (`livelab-1783135864-2fda3979d599`, commit `2fda397`): `validate_macos_role_transition` (`--role-switch-platform macos`) drove a real `LocalOnly` client->admin flip on `macos-utm-1` via `rustynet role set` + launchd bootout/bootstrap, asserted the new role via `role status`, ran `state refresh`, and asserted mesh peers did not regress across the flip (0 before/after, expected for a `--skip-linux-live-suite` run). `SignedMembership`-kind transitions (capability changes) are a separate follow-up. | 🔒 **stage built, BLOCKED 2026-07-04 on a real capability gap** (`validate_windows_role_transition`, commit `8816bf7`; first live run `livelab-1783142381-8816bf73333b` FAILED, isolated, no collateral damage): the only installed Windows CLI (`rustynet-windows-trust-cli.rs`) is a pure offline crypto tool with no daemon IPC client, so there is no Windows verb for `role status`/`role set`/`state refresh` yet; `update_node_role_env_file` also does not parse the Windows `RUSTYNETD_DAEMON_ARGS_JSON` array format. See `CrossOsRoleSwitchPlan_2026-06-24.md` status header for the full root-cause + required follow-up (a named-pipe IPC client + the env-file parser fix) |

## 4. The gap is LIVE PROVING + a few real impls — not (mostly) missing framework

The topology + validator **framework largely landed already** (see
`AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md` Track B — "all seven
steps landed": the `--exit-platform / --relay-platform / --anchor-platform`
topology selectors, macOS exit validators, the platform-aware role-transition
planner + per-OS exit/relay installers, the Windows active-exit promotion stage,
the macOS relay lifecycle dry-run, and `ops e2e-bootstrap-{macos,windows}`
non-Linux genesis verbs). What remains:

1. **Run each role green LIVE** on real macOS/Windows guests (the stages exist but
   are gated off / skipped / contract-only by default).
2. **Upgrade remaining contract/dry-run validators to live** — Windows relay
   still needs real session forwarding. macOS + Windows anchor bundle-pull are
   now live-proven; remaining anchor sub-surfaces (gossip_seed,
   enrollment_endpoint, port_mapping_authoritative) still need explicit live
   coverage.
3. **Close hard blockers** — chiefly a WinNAT/HNS-capable Windows lab guest for
   the exit role.
4. **Implement live cross-OS role transitions** (macOS launchd, Windows
   windows_service StateRefresh) per `CrossOsRoleSwitchPlan_2026-06-24.md`.
5. **Remaining role-transition and anchor-sub-surface parity** after the now
   live-proven macOS/Windows admin cells and macOS blind_exit cell.

## 5. Live-lab test matrix (acceptance — this is how we PROVE parity)

For every role R ∈ {exit, relay, anchor, admin, blind_exit} × OS ∈ {macOS, Windows}
there must be a recorded GREEN live-lab run that elects that OS into R and exercises
the role's **runtime** (not a contract/dry-run), with the row captured in
`documents/operations/live_lab_run_matrix.csv`.

Driver pattern (same CLI wrapper the loop uses):
```
target/debug/rustynet-cli ops vm-lab-orchestrate-live-lab \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --ssh-identity-file <key> --known-hosts-file <kh> --report-dir state/live-lab-<name> \
  --legacy-bash-orchestrator --stage-timeout-secs 1500 \
  --exit-vm debian-headless-1 --client-vm debian-headless-2 --entry-vm debian-headless-3 \
  --aux-vm macos-utm-1 --windows-vm windows-utm-1 \
  --<role>-platform <macos|windows>   # e.g. --exit-platform windows
  [--promote-... flags as the role requires]
  --skip-soak --source-mode local-head
```
Per role, the stage(s) that must move from contract/skip → live-green:
- **exit (macOS):** `is_macos_active_exit` path + `capture_macos_exit_evidence_artifacts` + `validate_macos_exit_*` (NAT lifecycle, DNS leak, killswitch precedence) — assert live client egress via the macOS node.
- **exit (Windows):** `promote_windows_exit_active` + `validate_windows_exit_nat_lifecycle` + `capture_windows_exit_evidence_artifacts` — asserts `route advertise 0.0.0.0/0` → forwarding + NAT + client egress (`Get-NetNatSession`). **Needs a WinNAT-capable guest.**
- **relay (Windows/macOS):** upgrade `validate_windows_relay_service_lifecycle_contract` / the macOS relay dry-run to a **live relay-forwarding** stage (a peer that can only relay actually forwards through the macOS/Windows relay).
- **anchor (Windows/macOS):** bundle-pull serving is live-proven on macOS and Windows (`validate_macos_anchor_bundle_pull`, `validate_windows_anchor_bundle_pull`); next coverage must prove gossip_seed / enrollment_endpoint / port_mapping_authoritative live.
- **admin (Windows/macOS):** live-proven. Latest macOS refresh: run
  `labrun-1783089250895-6139-0` on commit `831d41d`, stage
  `validate_macos_admin_issue` PASS: macos-utm-1 minted assignment authority,
  issued a signed assignment bundle for `client-1`, macOS verified the valid
  bundle, rejected rollback/tamper cases, and the Linux peer accepted the valid
  macOS-issued bundle while rejecting wrong-node/tampered variants.
- **blind_exit (Windows/macOS):** the destructive-transition + irreversible-exit serving path, with the immutability gate verified.
- **role transitions:** the `role_switch_matrix` stage driving a real transition on a macOS and a Windows node (see `CrossOsRoleSwitchPlan_2026-06-24.md`).

Each stage must verify the role's **security controls** live: kill-switch, DNS
fail-closed, signed-state verify-before-apply, anti-replay, default-deny ACL/route.

## 6. Known blockers + dependencies

- **Windows exit:** `windows-utm-1` lacks WinNAT/HNS (`MSFT_NetNat` class absent).
  Needs a WinNAT-capable Windows lab guest. Details + run command +
  WinNAT-readiness probe in `WindowsExitNodeRunbook_2026-06-04.md`.
- **Windows relay/anchor:** currently contract/dry-run validators — need live
  serving implementations + live stages.
- **macOS remaining parity:** admin, blind_exit, relay lifecycle, exit, anchor
  bundle-pull, and `LocalOnly` role transitions are live-proven; remaining
  macOS scope is anchor gossip/enrollment/port-map sub-surfaces plus the
  `SignedMembership` transition kind.
- **Cross-OS live role transitions:** macOS `LocalOnly` (admin<->client)
  LIVE-PROVEN 2026-07-04 (`validate_macos_role_transition`); Windows
  (`windows_service` reload) and the `SignedMembership` kind remain design-only
  — design at `CrossOsRoleSwitchPlan_2026-06-24.md` (note: Windows
  `StateRefresh` IPC already exists; reuse the single verified apply path
  `refresh_signed_state_with_reason`, never add a second/weaker one).
- **Lab connectivity prerequisites:** `HomelabConnectivityParityDeltaPlan_2026-05-21.md`
  (macOS/Windows tunnel connectivity gap vs Linux).

## 7. Consolidated references (this doc unifies these)

- `AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md` — framework that landed (Track B) + anchor live-lab (Track A).
- `WindowsExitAndRelayDeltaPlan_2026-05-10.md`, `WindowsExitNodeRunbook_2026-06-04.md` — Windows exit/relay specifics + WinNAT blocker.
- `WindowsLiveLabReadinessPlan_2026-05-31.md`, `WindowsLabVmStabilityAndSessionModel_2026-04-30.md` — Windows live-lab path.
- `HomelabConnectivityParityDeltaPlan_2026-05-21.md` — macOS/Windows connectivity gap.
- `NodeRoleTaxonomy_2026-05-21.md` / `NodeRoleTaxonomyExtension_2026-06-11.md` — role definitions + per-platform eligibility.
- `LiveLabExecutionEfficiencyPlan_2026-06-20.md` — how to run the labs efficiently.
- `CrossPlatformRoleParityRoadmap_2026-06-22.md` — **the execution roadmap for this mandate**: per-cell remaining work + effort, ordered program, file-by-file plans for the first cells, the FAIL-LOUD live-stage spec, the concurrent-Windows+macOS test pipeline, and the all-on-`main` workflow.
- `CrossOsRoleSwitchPlan_2026-06-24.md` — live cross-OS role-transition design (authored 2026-06-24; supersedes the gitignored `state/` path the role-transition cell previously cited).
- Code anchors: `crates/rustynet-cli/src/vm_lab/mod.rs` (`is_macos_active_exit`, `promote_windows_exit_active`, `validate_windows_{exit_nat_lifecycle,relay_service_lifecycle_contract,anchor_bundle_pull_plan_contract}`, `--*-platform` selectors); `crates/rustynetd/src/macos_exit_killswitch_precedence.rs` (pf); `crates/rustynetd/src/phase10.rs` + `windows_service.rs` (netsh/WFP); `crates/rustynet-cli/src/role_cli.rs` (role presets + transitions).

## 8. Definition of Done (cross-platform role parity)

Parity is complete only when, for **both macOS and Windows**, **every** role in §2
has:
1. a platform-native runtime implementation (no Linux-only assumption),
2. a **green live-lab run** recorded in `live_lab_run_matrix.csv` exercising that
   role's runtime on a real guest,
3. its security controls (fail-closed, default-deny, kill-switch, DNS
   fail-closed, verify-before-apply, anti-replay) verified live, and
4. a verification test (unit/integration + the live stage).

Until all cells in the §3 matrix are ✅, **Rustynet is not cross-platform
complete**, regardless of how polished Linux is.

## 9. Code-state verification notes (2026-06-24, code-only review)

A code-only audit (no live lab) confirmed the §3 symbols are about **live-proven**
status and remain accurate; the notes below record what is **code-complete /
live-PENDING** vs an actual implementation gap, so the remaining live runs are not
mistaken for missing code. The §3 symbols are intentionally NOT flipped — ✅ still
requires a recorded green live run.

- **admin (Windows/macOS) — superseded by live proof.** Windows admin is
  live-proven by `livelab-1782526081`; macOS admin is live-proven and refreshed
  by `labrun-1783089250895-6139-0` on commit `831d41d`. That macOS run passed
  `validate_macos_admin_issue` with signed-bundle issue, local valid verify,
  rollback rejection, tamper rejection, Linux peer verify-before-apply accept,
  and wrong-node/tamper rejection. The older "macOS self-mint disabled" note was
  stale and is no longer authoritative.
- **exit (macOS) — 🟡, security-hardened 2026-06-24.** The `pfctl -f` privileged
  boundary is closed (regeneration via the `macos-pf-load` builtin) and the exit-NAT
  teardown verifier now fails closed on an unverifiable capture (RSA-0031). Still needs
  a live green run.
- **blind_exit (macOS) — dataplane/control code-complete; orchestrator activation
  stage still deferred.** `macos_blind_exit.rs` + daemon invariants (`daemon.rs:8297`)
  + the immutability gate (`role_cli.rs:484-517`) + capability schema + unit tests are
  present, and the macOS lab `NodeRole::Exit` already maps to the daemon `blind_exit`
  role with `[BlindExit, ExitServer]` (`orchestrator/role.rs:120,148`). The remaining
  gap is a FAIL-LOUD activation/assertion **stage** (deferred in `active_exit.rs`),
  entangled with the macOS exit path and only meaningful live.
- **Windows anchor / relay — see the §10 correction (2026-06-24).** Windows
  **anchor** bundle-pull serving IS genuinely unbuilt (the daemon loopback listener
  is wired only into the `#[cfg(not(windows))]` main loop — needs cfg(windows)
  wiring + a live stage). Windows **relay** lifecycle is contract-complete; its
  only gap is HP-3 live forwarding, which is unproven on **every** OS (not a
  Windows runtime hole — §9's "genuinely unbuilt" framing for relay was stale).
- **Tooling blocker for Windows-only code:** on the dev macOS host, `cargo check
  --target x86_64-pc-windows-gnu` fails compiling deps (`cpufeatures`/`subtle`), so new
  `cfg(windows)`-only code (e.g. DPAPI/SDDL key custody RSA-0002/0025) is **not locally
  gate-verifiable** — those items need a Windows builder or CI cross-check.

## 10. Second code audit + fixes (2026-06-24, workflow-verified, no live lab)

A 7-cell parallel code audit (each agent reading the actual symbols, file:line)
re-checked §9 and found it **partially stale**. Authoritative per-cell state and
the fixes landed this pass (all Linux-gate-verified; live runs still pending):

- **macOS blind_exit — §9 was STALE; cell is code-complete.** §9 said the live
  stage was "deferred in `active_exit.rs`"; that inspected only the rust-native
  stage. The FAIL-LOUD live stage exists in the legacy path
  (`validate_macos_blind_exit` `vm_lab/mod.rs:9693` → `exercise_macos_blind_exit_live`
  `:10371`: irreversible `role set blind_exit --accept-irreversible`, asserts the
  pf anchor loaded + no route-to/reply-to/dup-to + the immutability gate). With
  the runtime + the 2026-06-24 mesh-CIDR bound, only a live run remains. §3 fixed.
- **Windows exit — WAS code-incomplete (§10.7 residue gap); NOW code-complete.**
  `WindowsCommandSystem` had no `reconcile_exit_nat_residue` override (default
  no-op), so a crash-while-serving-exit → restart-as-client could not self-heal
  the fixed-name `New-NetNat` + enabled forwarding (the in-memory rollback state
  is lost on crash). **Fixed this pass** (`phase10.rs`,
  `windows_exit_nat_residue_plan` + the override + a Linux pure-function test):
  when not serving, `Remove-NetNat` by fixed name + force forwarding Disabled on
  the tunnel + egress interfaces, best-effort, only-when-not-serving. The
  WinNAT/`MSFT_NetNat` live blocker is unchanged.
- **Windows anchor — bundle-pull LIVE-PROVEN 2026-07-03.** The bundle-pull listener was wired into the `#[cfg(windows)]`
  reconcile loop (`daemon.rs`): the bind + accept/serve were extracted into two
  portable, Linux-unit-tested helpers (`bind_anchor_bundle_pull_listener`,
  `poll_anchor_bundle_pull_once`) shared by both the Unix and Windows loops, so a
  Windows anchor now opens `127.0.0.1:51822` and serves verify-before-serve,
  token-gated bundle-pull. Run `labrun-1783079551578-32671-0` on commit
  `786f900` passed `validate_windows_anchor_bundle_pull` live on `windows-utm-1`
  with loopback byte-for-byte, token-gate, LAN-refused, and secrets-hygiene
  assertions. **Remaining:** gossip/enrollment_endpoint/port-map anchor surfaces
  still need explicit Windows live proof beyond the bundle-pull cell.
- **Windows relay — §9 was STALE (it called this "genuinely unbuilt").** The
  cell is **lab-blocked-code-complete for lifecycle**; the real gap is HP-3 live
  forwarding, which is unproven on **every** OS (not Windows-specific). The
  Windows relay SCM lifecycle is contract-validated; forwarding is the
  cross-cutting HP-3 item, not a Windows runtime hole.
- **macOS exit — LIVE-PROVEN for regular-exit activation/NAT/DNS/audit tail
  (2026-07-03).** Run `labrun-1783087254263-11121-0` from commit `039f215`
  reran the `--macos-promote-exit` path after the audit-tail fix and produced no
  failed stages. The elected macOS exit scope passed `activate_macos_exit_role`,
  `capture_macos_exit_evidence_artifacts`, `validate_macos_exit_nat_lifecycle`,
  `validate_macos_exit_dns_failclosed`, `validate_macos_service_hardening`, and
  `validate_macos_mesh_status` (fresh daemon-owned state snapshot, `age_seconds=5`).
  The run is recorded as `partial` only because out-of-scope/optional stages
  skipped: full Linux suite by selector, optional IPv6/killswitch artifacts, and
  non-elected macOS anchor/admin/blind_exit roles. This supersedes the earlier
  failed run `labrun-1783084800049-93461-0` on commit `709ca9f`, which exposed
  the stale service-hardening passphrase path and unprivileged mesh-status read.
- **macOS/admin/relay context.** Windows admin, macOS admin, and macOS relay
  (lifecycle) are now **LIVE-PROVEN**. macOS admin refresh
  `labrun-1783089250895-6139-0` from clean commit `831d41d` passed
  `validate_macos_admin_issue`; macOS relay flipped ✅ 2026-06-27 via the
  `--relay-platform macos` orchestrate stage, run `livelab-1782571161`,
  `cd6a834`. The only consistent CODE gap is
  that none of the mac/win FAIL-LOUD stages have a Linux-buildable **contract
  test for their gating decision matrix** (dry-run→Skip, not-elected→Skip,
  mesh-join-not-pass→Skip, live-ok→Pass, live-err→Fail) — addable by factoring
  the gating out of the live SSH call.
- **Live cross-OS role transitions — genuinely unbuilt (Linux-authorable).**
  `RoleSwitchMatrixStage` is a passive tunnel-health check; no stage selects a
  mac/win node as a role-switch TARGET, drives the platform role-set flip
  (launchd reload / `windows_service`), and re-applies signed state via
  `StateRefresh`/`refresh_signed_state_with_reason`. Design now in
  `CrossOsRoleSwitchPlan_2026-06-24.md`; the stage itself is the remaining work
  (Linux-buildable, but only meaningful when run live against mac/win guests).
  **UPDATE 2026-07-04: the macOS `LocalOnly` slice of this is now built AND
  live-proven** (`validate_macos_role_transition`, run
  `livelab-1783135864-2fda3979d599`) — see §3 above. This note's diagnosis
  stays accurate for the Windows half and the `SignedMembership` kind.

**Net remaining parity CODE work (no live lab):** (a) a Windows CLI IPC
client (named-pipe) for `role status`/`role set`/`state refresh` + fixing
`update_node_role_env_file` to parse the `RUSTYNETD_DAEMON_ARGS_JSON` array
format, discovered blocking `validate_windows_role_transition`'s first live
run 2026-07-04 (macOS `LocalOnly` landed the same day); (b) the
`SignedMembership` transition kind for both OS; (c) the mac/win
stage-gating contract tests (Linux-authorable, small); (d) explicit live
stages for the remaining anchor sub-surfaces beyond bundle-pull
(gossip_seed, enrollment_endpoint, port_mapping_authoritative). Everything
else is code-complete-live-pending or HP-3/WinNAT-blocked.

## 11. Live-lab honesty pass (2026-06-25, code-only, no live lab)

A read-only "will the un-run stages pass, and do they prove what they claim?"
audit found stages reporting a live **Pass** from checks that never touched the
guest, fail-open teardown proofs, and vacuous captures. Fixes landed (gates
green; cfg(macos)/cfg(windows) runtime is not Linux-compile-checkable so only the
pure logic + non-target stubs + unit tests verify here). Full detail in
`AutonomousSecurityParityPassLog_2026-06-24.md` (§ "Live-lab honesty pass"):

- **Two Windows contract stages no longer fake a live Pass.**
  At the 2026-06-25 honesty pass, `validate_windows_anchor_bundle_pull`
  (in-process anchor-init plan-string check) and
  `validate_windows_relay_service_lifecycle` (static `.ps1` lint) recorded
  **Skipped** ("contract-only — NOT live-proven"); a contract violation stayed
  **Fail**. This kept the Windows anchor/relay cells out of live-proven
  aggregates until guest-touching stages existed. The anchor half was
  superseded on 2026-07-03 by run `labrun-1783079551578-32671-0`; Windows relay
  lifecycle/forwarding remains contract/HP-3-gated.
- **Windows-exit + macOS-exit teardown captures made fail-closed** (RSA-0031
  parity): a `Get-NetNat`/forwarding/sysctl query error is treated as
  still-present / not-restored (no default-to-`Disabled`), and the Windows
  lifecycle artifact is always emitted once serving so a residual NAT (open
  relay) **Fails** instead of being masked as a Skip.
- **macOS exit DNS leak proof is no longer vacuous:** an active off-tunnel DNS
  probe (`dns_block_probe.json`) is now required so an empty egress pcap proves
  the killswitch dropped real traffic.

**Honestly-documented remaining gap (already fail-closed, NOT a cheat):** the
macOS exit **client-egress NAT-session** assertion (`active_exit.rs:29-33`) —
macOS Exit maps to `blind_exit` (enforce-time pf NAT, anchor hard-locked across
cleanup), which does not fit the activate→assert→nat-session shape, so the macOS
adapter keeps the fail-closed default. The exit-NAT *lifecycle* (serving during
run + clean teardown) is proven; a live translated-client-session through the
macOS pf NAT remains a scoped follow-up (needs the two-node activate→assert path
reworked for macOS's enforce-time model). The same empty-pcap-vacuity fix is a
follow-up for the **Linux** and **Windows** exit DNS proofs (this pass scoped the
active probe to macOS as requested).
