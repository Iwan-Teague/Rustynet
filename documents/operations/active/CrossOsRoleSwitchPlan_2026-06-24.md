# Cross-OS Live Role-Transition Design — 2026-06-24

> **Status: macOS `LocalOnly` (admin<->client) slice IMPLEMENTED 2026-07-04,
> pending live-lab proof.** `exercise_macos_role_transition_live` (`crates/
> rustynet-cli/src/vm_lab/mod.rs`) drives the real §5 sequence — `rustynet
> role set <to>` → `launchctl bootout`/`bootstrap` → assert new role via
> `role status` → `rustynet state refresh` → assert mesh peers survived the
> flip — gated behind a new `--role-switch-platform macos` selector
> (`validate_macos_role_transition` stage, `live_lab_stage_registry.rs`).
> Windows (`windows_service` reload) and the `SignedMembership` transition
> kind (capability changes, needs the admin issue/ingest wiring) remain
> design-only — see §3/§4 below, unchanged. This is the banked design the
> `CrossPlatformRoleParityPlan_2026-06-21.md` §3 *live role transitions
> (cross-OS)* cell depends on (Roadmap `CrossPlatformRoleParityRoadmap_2026-06-22.md`
> §4 cell #4). It supersedes the previously-cited `state/cross_os_role_switch_plan.md`,
> which could not persist in the repo because `/state/**` is `.gitignore`d (it
> holds ephemeral live-lab run reports). Future references should point here.

## 1. Goal

A node must be able to transition between roles **live** on macOS (launchd) and
Windows (`windows_service`) exactly as Linux (systemd) does today — flip the
role, re-apply signed state through the **one** verified apply path, and prove
the new role's dataplane is active — with no OS-specific weakening of the
fail-closed / default-deny / verify-before-apply posture.

Linux is the reference: the orchestrator's `role_switch_matrix` stage
(`crates/rustynet-cli/src/vm_lab/orchestrator/stage/role_switch_matrix.rs`)
already runs cross-OS, but today it only *verifies tunnels stayed active* after
role distribution (`verify_tunnels_active`) — it does **not drive a real flip**.
Closing the cell means authoring a stage that performs an actual transition and
asserts the destination role's runtime.

## 2. The single verified apply path (reuse — never fork)

`Daemon::refresh_signed_state_with_reason` (`crates/rustynetd/src/daemon.rs:4487`)
is the **only** path that re-applies signed state, and it fails closed on every
fetch error:

1. `fetch_trust` → 2. `fetch_traversal` → 3. `fetch_assignment` (when
   `auto_tunnel_enforce`) → 4. `fetch_dns_zone` → 5. `load_verified_trust`.

Each step verifies signature → freshness/replay watermark → apply (CLAUDE.md
§10.5). It is triggered by the `StateRefresh` IPC command (`ipc.rs:44`,
dispatched at `daemon.rs:7157`), which the CLI already issues via
`execute_state_refresh`.

**Hard rule (matches the parity plan §6 note):** the cross-OS role-flip MUST
reuse this path + `StateRefresh`. Do **not** add a second, OS-specific, or
weaker apply branch. One hardened path per security-sensitive workflow
(CLAUDE.md §3).

## 3. Per-OS role-flip mechanics (the only OS-specific seam)

The role *decision* and *side-effects* are platform-neutral
(`role_cli::plan_concrete_actions` → `TransitionKind` + ordered
`ConcreteAction`s; `role_presets::TransitionPlan`). Only **how the daemon learns
its new role** differs by OS:

| OS | Role source the daemon reads | How `role set` flips it | How the daemon re-reads it |
|---|---|---|---|
| Linux | `--node-role` argv, env file `/etc/default/rustynetd` | `WriteNodeRoleEnv` (atomic env rewrite) | systemd restart |
| macOS | `--node-role` argv pair in `com.rustynet.daemon.plist` (no env fallback) | rewrite the plist `--node-role` pair (`update_node_role_macos_plist`) | `launchctl bootout` + `bootstrap` (a `kickstart -k` does **not** re-read an edited plist — proven live, parity plan §3 exit row) |
| Windows | service `ImagePath` / config | reviewed PowerShell helper writes role | `windows_service` `StateRefresh` IPC (reuse the verified apply path; never a second one) |

These mechanics already exist and are individually proven; the gap is wiring
them into a transition *stage* that exercises them end-to-end.

## 4. Transition kinds and their ordering invariants

From `role_presets::TransitionKind` (already enforced in `role_cli.rs`):

- **LocalOnly** (e.g. admin ↔ client): config write + daemon reload, **no signed
  bundle**. After reload, `StateRefresh` re-applies signed state; assert the new
  primary role's dataplane.
- **SignedMembership** (capability change): emit an unsigned
  `MembershipUpdateRecord`, the admin signs it, the node ingests it via the
  verified apply path. **deploy-before-advertise / undeploy-before-revoke**
  ordering is mandatory (exit NAT torn down *before* capability removal;
  relay/nas/llm service deployed *before* the signed advertisement) — this is
  Tailscale's exit/relay double-opt-in discipline (Roadmap Appendix A #6).
- **Irreversible** (`blind_exit`): typed factory-reset acknowledgement;
  matrix-enforced one-way (`role_cli.rs` `BlindExitImmutable`). Re-enrollment
  after the wipe MUST route through the **single-use, client-side-keygen, scoped
  enrollment-token** path and mint a brand-new device keypair — never reuse the
  pre-reset identity (Roadmap Appendix A #8/#14, item #5 risk-avoid).

`emit_role_audit` now fails closed for SignedMembership/Irreversible transitions
(RSA-0014), so a transition that cannot be durably audited does not silently
"succeed".

## 5. FAIL-LOUD stage design (per Roadmap §7)

Author a `role_switch_matrix`-adjacent stage (or extend it behind an explicit
`--role-switch-platform <macos|windows>` selector) that, for the elected node:

1. Records the **before** role + asserts its dataplane is the expected one.
2. Drives a **real** flip: `rustynet role set <to>` over SSH (composing
   `user@host` from inventory `ssh_user` + `ssh_target` — never hardcode the
   user), applying the per-OS reload from §3.
3. For a SignedMembership flip, has the **admin node issue + sign** the
   capability bundle and the transitioning node **ingest** it via `StateRefresh`
   → the verified apply path (depends on the admin cell #1/#2).
4. Asserts the **after** role's dataplane is live (the new capability's anchor /
   route / service is present; the killswitch + DNS fail-closed still hold).
5. **Status = the live result.** A `--dry-run`/plan render is informational
   only, never a Pass. An unverifiable node (e.g. `wg-not-installed`) is a
   **Fail**, never a silent pass — reuse `verify_tunnels_active`'s no-fake-pass
   contract. Record the row in `live_lab_run_matrix.csv`.

Security controls asserted live: signed-state verify-before-apply (signature →
watermark → apply), anti-replay, default-deny ACL/route, kill-switch and DNS
fail-closed across the flip, and the deploy/undeploy ordering for capability
changes.

## 6. Dependencies & sequencing

- **Depends on admin (cells #1/#2):** the SignedMembership half needs a node
  that can mint + issue a signed capability bundle (macOS `validate_macos_admin_issue`
  / Windows `validate_windows_admin_issue` patterns).
- **Sequence after admin** in the parity program (Roadmap §5).
- **Reuses, does not fork,** `refresh_signed_state_with_reason` + `StateRefresh`.

## 7. Acceptance (Definition of Done for the cell)

- A green live-lab run drives a real role flip on a macOS node **and** a Windows
  node, re-applies signed state through the verified path, and asserts the new
  role's dataplane — recorded in `live_lab_run_matrix.csv`.
- The stage + its unit/contract tests exist, compile, and follow §5 (no
  dry-run-as-pass; unverifiable = Fail).
- Security controls (verify-before-apply, anti-replay, default-deny, kill-switch,
  DNS fail-closed, deploy/undeploy ordering) verified live.

## 8. Code anchors

- Apply path: `crates/rustynetd/src/daemon.rs:4487` (`refresh_signed_state_with_reason`),
  `crates/rustynetd/src/ipc.rs:44` + `daemon.rs:7157` (`StateRefresh`).
- Stage: `crates/rustynet-cli/src/vm_lab/orchestrator/stage/role_switch_matrix.rs`.
- Role planner / kinds: `crates/rustynet-cli/src/role_cli.rs`,
  `crates/rustynet-control/src/role_presets.rs` (`TransitionKind`,
  `TransitionPlan`, `requires_owner_signature`).
- Per-OS flip: `update_node_role_macos_plist` / `update_node_role_env_file`
  (`crates/rustynet-cli/src/main.rs`), `crates/rustynetd/src/windows_service.rs`.
- Audit fail-closed: `finalize_role_audit` (`crates/rustynet-cli/src/main.rs`, RSA-0014).
