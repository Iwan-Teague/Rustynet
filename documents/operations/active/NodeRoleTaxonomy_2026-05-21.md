# Rustynet Node Role Taxonomy

- Date: 2026-05-21
- Status: active (design source-of-truth for the user-selectable node role surface)
- Owner: Rustynet
- Supersedes nothing. Promotes the existing scattered role logic (`NodeRole` enum at `crates/rustynetd/src/daemon.rs:960`, exit-serving derived state, separate `rustynet-relay` binary, planned anchor capabilities from [`AnchorNodeRoleDesign_2026-05-21.md`](./AnchorNodeRoleDesign_2026-05-21.md)) into one cemented, per-device user-selectable surface.

---

## 0) Purpose of this document

Today, "what role does this device play in the mesh" is answered by reading several different code paths:

- `NodeRole` enum (`Admin / Client / BlindExit`) controls local CLI permissions and dataplane posture (`daemon.rs:960`)
- Exit-serving is a derived state from `route advertise 0.0.0.0/0` + `NodeRole::Admin`, OR auto-on for `NodeRole::BlindExit` (`daemon.rs:7130 is_serving_exit_node`)
- Relay is a separate binary (`rustynet-relay`) deployed as a separate service, with no role-CLI surface
- Anchor capabilities are planned (D11) but not yet a user-facing concept

This document **cements** six user-facing roles into a single per-device selection:

`relay` | `anchor` | `exit` | `blind_exit` | `client` | `admin`

The user picks one role per device. The daemon, installer, and signed membership state compose all underlying primitives (local-permission, capability advertisement, service deploy, NAT activation, port-mapping, gossip seed priority) to match.

If a later document or commit conflicts with this design, this document is the source of truth for the role taxonomy until it is explicitly superseded.

---

## 1) Why a single role selection (not multiple toggles)

User feedback (2026-05-21):

> can we cement these roles? relay, anchor, exit node, blindexit, client, admin. These should be selectable by the user for each device

The product decision is **one role per device**. Reasons:

- **Operator simplicity.** "What is this box?" should have one answer, not six checkboxes.
- **Security clarity.** Each role has a known security posture (least-knowledge, exit-serving, relay-only, etc.). Composing arbitrary capability subsets makes posture review harder.
- **Documentation tractability.** Per-role runbooks, hardening guidance, and audit trails are easier to write when the role is a closed set of named compositions.
- **Wizard UX.** `start.sh` and `rustynet operator menu` need a flat dropdown, not a multi-select.

The **internal data model** stays two-axis (see §3) so power users can still compose non-preset arrangements via advanced CLI verbs — but the default UX presents six named choices.

---

## 2) The six roles (user-facing presets)

| Role | Plain English | Internal composition |
|---|---|---|
| `client` | "This is my laptop / phone-equivalent. It uses the mesh, it doesn't host anything." | Primary=Client, no extra capabilities |
| `admin` | "This is my admin workstation. I can issue bundles, switch roles, manage policy from here." | Primary=Admin, no extra capabilities |
| `exit` | "This box should serve internet egress to other peers in the mesh." | Primary=Admin, `serves_exit=true`, advertises `0.0.0.0/0` |
| `blind_exit` | "This box is a hardened final-hop exit. No local control surface beyond status checks. Immutable." | Primary=BlindExit, `serves_exit=true` (forced), local mutation blocked |
| `relay` | "This box should forward encrypted UDP between peer pairs that can't direct-connect." | Primary=Admin, `serves_relay=true`, `rustynet-relay` co-deployed |
| `anchor` | "This is my always-on home box. It seeds gossip, hosts bundle-pull + enrollment endpoints, owns the router port-mapping lease, and forwards relay traffic." | Primary=Admin, all five `anchor.*` capabilities (`gossip_seed`, `bundle_pull`, `enrollment_endpoint`, `relay_colocation`, `port_mapping_authoritative`) — see [`AnchorNodeRoleDesign_2026-05-21.md`](./AnchorNodeRoleDesign_2026-05-21.md) |

Each role is a **complete composition**. Picking `anchor` does not require also picking `relay` (anchor includes relay co-location).

**Excluded from base roles** (advanced/composite use cases):

- `anchor + exit` (anchor that also serves internet egress). Available via `rustynet capability add serves_exit` after picking `anchor`. Common for home-server-as-everything deployments.
- Custom subsets of anchor capabilities (e.g., `gossip_seed` only). Available via `rustynet capability add anchor.gossip_seed` etc. Operator-mode only.
- `relay + admin` is just `relay` since relay role implies Primary=Admin.

The advanced-mode verbs (`rustynet capability {add,remove,list}`) ship as part of D12 alongside the preset surface, but the wizard never shows them — they are CLI-only for power users who need non-standard compositions.

---

## 3) Internal data model (two-axis)

The data model behind the six presets:

### 3.1 Axis 1 — Primary role (mutually exclusive)

Lives in local config (`NodeRole` enum in `crates/rustynetd/src/daemon.rs:960`). Controls:

- which IPC commands the daemon accepts (`allows_command`)
- whether `is_serving_exit_node` auto-returns true (only for BlindExit)
- whether dataplane route sanitisation strips exit routes (`sanitize_dataplane_routes_for_node_role`)
- start.sh role-switch and `rustynet role` CLI gating

Variants stay at: `Admin / Client / BlindExit`. No new variants added — `Anchor`, `Relay`, `Exit` are NOT new `NodeRole` variants; they are presets that select `NodeRole::Admin` + a capability set.

### 3.2 Axis 2 — Mesh capabilities (composable, signed)

Lives in the signed membership bundle (per-node entry, optional field). Capabilities:

| Capability | What it does |
|---|---|
| `serves_exit` | Daemon applies forwarding + NAT for `0.0.0.0/0`. Other peers may select this node as their exit (subject to assignment-bundle authorisation). |
| `serves_relay` | `rustynet-relay` runs as a sibling service on this host. Other peers can use it as fallback when direct-connect fails. |
| `anchor.gossip_seed` | Priority gossip rebroadcast (see [`AnchorNodeRoleDesign_2026-05-21.md`](./AnchorNodeRoleDesign_2026-05-21.md) §2). |
| `anchor.bundle_pull` | LAN-loopback bundle-pull endpoint for new-device bootstrap. |
| `anchor.enrollment_endpoint` | LAN-loopback enrollment-token redemption endpoint. |
| `anchor.relay_colocation` | Indicates the relay co-deploys on this host (folds into / equivalent to `serves_relay` for relay-only nodes; distinct field on anchor presets for telemetry clarity). |
| `anchor.port_mapping_authoritative` | This node holds the uPnP/PCP/NAT-PMP lease for its LAN. Multi-anchor coordination uses lex-min node-id. |

**Critical invariant:** Capabilities live in signed membership. A node cannot self-promote. The membership owner signs a bundle that grants/revokes capabilities. The daemon reads its own capability set from the signed bundle on bootstrap + on reload.

### 3.3 Preset → composition mapping (authoritative)

| Preset | Axis 1 | Axis 2 capabilities |
|---|---|---|
| `client` | `Client` | (none) |
| `admin` | `Admin` | (none) |
| `exit` | `Admin` | `serves_exit` |
| `blind_exit` | `BlindExit` | `serves_exit` (forced) |
| `relay` | `Admin` | `serves_relay` |
| `anchor` | `Admin` | `anchor.gossip_seed`, `anchor.bundle_pull`, `anchor.enrollment_endpoint`, `anchor.relay_colocation`, `anchor.port_mapping_authoritative` (implies `serves_relay` via `anchor.relay_colocation`) |

The mapping is stored in code as a `pub const ROLE_PRESET_TABLE` lookup in a new `crates/rustynet-control/src/role_presets.rs` module. Tests pin the mapping against this table so any future preset change has a single source of truth.

---

## 4) CLI surface

### 4.1 New verbs

```
rustynet role set <preset>
rustynet role status
rustynet role list
rustynet role transition-check --to <preset>
```

| Verb | Behaviour |
|---|---|
| `role set <preset>` | Validates the requested transition is allowed (see §5). If preset changes only the local-Axis-1 (admin↔client), updates local config + reloads daemon. If preset changes Axis-2 capabilities, emits an unsigned `MembershipUpdateRecord` (same shape as `rustynet enrollment admit`) for the admin to sign + apply. Fails closed on disallowed transitions. |
| `role status` | Prints current preset (resolved from local Axis 1 + signed Axis 2), plus capability list. Available to all roles. |
| `role list` | Prints the six presets + a one-line description each. Available to all roles. |
| `role transition-check --to <preset>` | Dry-run: reports whether the current → target transition is allowed and what state changes it would emit (local config writes, signed bundle requests, service deploys). Available to admin only. |

### 4.2 Existing `rustynet capability {add,remove,list}` (advanced)

| Verb | Behaviour |
|---|---|
| `capability add <flag>` | Admin-only. Emits an unsigned `MembershipUpdateRecord` adding one capability. Operator signs + applies. |
| `capability remove <flag>` | Admin-only. Emits an unsigned `MembershipUpdateRecord` removing one capability. Operator signs + applies. Capability removals validate that the node is not depended-on by other peers (e.g., cannot remove `serves_exit` from a node currently named in any peer's assignment bundle as exit-node). |
| `capability list` | All roles. Prints current signed capability set with provenance (which bundle epoch granted each). |

These are NOT shown in the wizard. Reserved for power users. Documented in `documents/operations/RustynetdServiceHardening.md`.

### 4.3 IPC verbs added

New `IpcCommand` variants:

```rust
IpcCommand::RoleSet(String),         // preset name
IpcCommand::RoleStatus,
IpcCommand::RoleTransitionCheck(String),
IpcCommand::CapabilityAdd(String),
IpcCommand::CapabilityRemove(String),
IpcCommand::CapabilityList,
```

All gated by `NodeRole::Admin` (except `RoleStatus` + `CapabilityList`, available to Client and BlindExit read-only).

---

## 5) Role transitions (reversibility matrix)

Not every transition is allowed. Some are local-only (cheap), some require a signed membership bundle (operator signs), some are irreversible.

Cell legend:
- `local` — daemon-local change only (config write + reload)
- `signed` — emits unsigned update record; admin must sign + apply
- `blocked` — transition not allowed; fail-closed
- `irrev` — irreversible without factory reset

| From ↓ \ To → | client | admin | exit | blind_exit | relay | anchor |
|---|---|---|---|---|---|---|
| **client** | — | `local` | `local + signed` | `irrev` | `local + signed + service-deploy` | `local + signed + service-deploy` |
| **admin** | `local` | — | `signed` | `irrev` | `signed + service-deploy` | `signed + service-deploy` |
| **exit** | `signed + local` | `signed` | — | `irrev` | `signed + service-deploy` | `signed + service-deploy` |
| **blind_exit** | `blocked` | `blocked` | `blocked` | — | `blocked` | `blocked` |
| **relay** | `signed + service-undeploy + local` | `signed + service-undeploy` | `signed + service-undeploy` | `irrev` | — | `signed + service-deploy` |
| **anchor** | `signed + service-undeploy + local` | `signed + service-undeploy` | `signed + service-undeploy` | `irrev` | `signed + service-undeploy` | — |

Rules captured in the matrix:

- **BlindExit is one-way (`irrev`).** Once a node is `blind_exit`, switching out requires factory reset + fresh key provisioning. Matches current `NodeRole::BlindExit` immutability. Hardened by design.
- **Becoming BlindExit is also `irrev`** — promoting a regular node to `blind_exit` triggers key wipe + reset to a fresh `BlindExit` identity (membership re-enrollment). The transition can be initiated, but it is destructive and irreversible.
- **Service-deploy / undeploy** — relay and anchor presets co-deploy `rustynet-relay` as a sibling systemd / launchd / SCM service. Switching out of relay or anchor MUST undeploy the service (fail-closed on failure). Switching in MUST deploy it before the capability is advertised in the signed bundle (deploy-then-advertise to avoid signalling a capability the host can't actually serve).
- **`exit` ↔ `client` requires signed** — going from exit-server back to client revokes the `serves_exit` capability. Other peers that currently route via this node lose their exit; their assignment bundles must be re-issued without this node. The bundle revocation is a signed-membership operation.
- **Multi-anchor coordination is implicit** — switching to `anchor` does NOT auto-grant `port_mapping_authoritative` if another anchor already holds the lease for this LAN. The capability is granted (preset says so) but runtime coordination defers via lex-min.

### 5.1 Transition flow examples

**Client → exit (with signed bundle):**

```
operator-on-target-box$ rustynet role set exit
→ validates transition is allowed
→ writes unsigned MembershipUpdateRecord to /tmp/role-transition.record
→ prints: "transition emitted; sign with membership owner key on admin box"

operator-on-admin-box$ rustynet membership apply-update \
    --record /tmp/role-transition.record \
    --signing-secret /etc/rustynet/membership.owner.key \
    --signing-secret-passphrase-file ...
→ signs + applies to local snapshot
→ gossip propagates to all peers

operator-on-target-box$ rustynet role status
→ "exit (resolved from primary=admin, capabilities=[serves_exit])"
→ daemon now applies forwarding + NAT for 0.0.0.0/0
```

**Admin → relay (deploy):**

```
operator-on-target-box$ rustynet role set relay
→ validates
→ deploys rustynet-relay.service (systemd) / RustyNetRelay (SCM) / com.rustynet.relay.plist (launchd)
→ verifies service is Running
→ THEN emits unsigned MembershipUpdateRecord with serves_relay=true
→ prints: "service deployed; sign + apply the record"
```

**Anchor → admin (undeploy):**

```
operator-on-target-box$ rustynet role set admin
→ emits unsigned MembershipUpdateRecord revoking all anchor.* capabilities
→ admin signs + applies on admin box
→ on apply, target daemon stops the bundle-pull listener, releases the port-mapping lease, stops priority gossip rebroadcast
→ undeploys rustynet-relay.service
→ if anchor.port_mapping_authoritative was active and another anchor exists on the same LAN, the next-lex-min anchor picks up the lease
```

---

## 6) Wizard surface

### 6.1 `start.sh` (Linux / macOS host profile)

Existing prompt:
```
Select node role:
1) admin    — full operational console
2) client   — limited console (status + connect/disconnect)
3) blind_exit — hardened final-hop exit (Linux only)
```

New prompt (D12):
```
Select node role:
1) anchor      — always-on home box: gossip seed + relay + bundle-pull + enrollment endpoint (recommended for one device per mesh)
2) admin       — admin workstation: full operational console; no extra mesh duties
3) exit        — internet egress for other peers (advertises 0.0.0.0/0)
4) relay       — encrypted UDP forwarding for peers that can't direct-connect
5) client      — uses the mesh; hosts nothing
6) blind_exit  — hardened final-hop exit (Linux only; IMMUTABLE — factory reset to change)
```

The wizard:
- Validates platform eligibility (see §7) before showing each option.
- Auto-detects existing role and offers transition-aware UX (e.g., shows `blind_exit` greyed out if current role is `blind_exit`, with explanatory note about factory reset).
- For `anchor`, `relay`, `exit` — prompts for service-deploy confirmation if it would install a new system service.
- For `blind_exit` — shows a one-line confirmation prompt with the irreversibility warning + requires typed "yes" (not just Enter).

### 6.2 `rustynet operator menu` (Rust-native menu)

Mirror the start.sh prompt. Same six options, same gating. Same transition-aware behaviour.

### 6.3 Mobile (iOS / Android)

Mobile clients are `client` role only (per §7). The wizard surface on mobile shows the role as a read-only status entry: "Role: client (mobile)". No selector.

---

## 7) Per-platform role eligibility

Not every platform can host every role. Mobile platforms are client-only by OS constraint.

| Role | Linux | macOS | Windows | iOS | Android |
|---|---|---|---|---|---|
| `client` | yes | yes | yes (today: `runtime-host-capable only`; full client when D7/D9 land) | yes | yes |
| `admin` | yes | yes | yes (same Windows gate) | no | no |
| `exit` | yes | yes (with admin-installed network tools) | yes (gated on D7 NetNat + killswitch evidence) | no | no |
| `blind_exit` | yes | no (PF-based killswitch parity work needed; defer until macOS exit parity proven) | no (gated behind Windows-as-blind-exit work, not in current dataplane plan) | no | no |
| `relay` | yes | yes | yes (gated on D7/D9; `rustynet-relay` already builds with SCM feature) | no | no |
| `anchor` | yes | yes | yes (gated on D7/D9) | no (consume-only; see anchor design §6.4) | no (consume-only; see anchor design §6.5) |

**Mobile is `client` only.** OS constraints (lifecycle suspension, address instability, sandboxing) prevent hosting any other role. Mobile clients consume the services of anchor/relay/exit roles on other peers; the mobile UI shows a read-only "Role: client (mobile)" indicator. Future mobile capability expansion is not in scope.

**Windows is gated.** Today `runtime-host-capable only`. All non-client roles on Windows land when D7/D9 in the dataplane plan complete (same prerequisite as Windows-as-exit). The wizard shows blocked roles greyed out with a one-line "blocked until Windows dataplane parity" note.

**macOS `blind_exit` is blocked.** Existing `start.sh` already enforces `blind_exit` is Linux-only (per CLAUDE.md project notes). The wizard maintains this; D12 does not extend `blind_exit` to macOS without separate work on PF-based killswitch parity.

---

## 8) What needs building

Five sub-slices. Map to D12 in the dataplane execution plan. Each track stands alone; A is a prerequisite for the rest.

### 8.1 D12.a — Preset table + transition validator (foundation)

| File | Change |
|---|---|
| `crates/rustynet-control/src/role_presets.rs` (new) | `pub const ROLE_PRESET_TABLE: &[(Preset, Primary, &[Capability])]` — authoritative mapping. Plus `validate_transition(from, to) -> TransitionPlan` returning local/signed/blocked/irrev + the side-effects (service deploy, bundle records, etc.). |
| `crates/rustynet-control/src/membership.rs` | Extend `NodeCapabilities` (added in D11.a) with `serves_exit`, `serves_relay`, `anchor.relay_colocation`, etc. Update canonical-payload pre-image (append-only). |
| Tests | Round-trip every preset through the table; assert every transition cell in §5 matches `validate_transition`; tamper tests on capability field. |

Estimated cost: 2 cycles.

### 8.2 D12.b — CLI surface

| File | Change |
|---|---|
| `crates/rustynet-cli/src/main.rs` | New verbs: `role {set, status, list, transition-check}`, `capability {add, remove, list}`. Parse + dispatch. |
| `crates/rustynet-cli/src/role_set.rs` (new) | Orchestrator for `role set`: resolve current role, compute transition plan, execute side-effects in order (deploy service → local config write → emit signed record → instruct operator). |
| `crates/rustynetd/src/daemon.rs` | Handle new IPC commands (`RoleSet`, `RoleStatus`, `RoleTransitionCheck`, `CapabilityAdd/Remove/List`). Gate per `NodeRole`. |

Estimated cost: 3 cycles.

### 8.3 D12.c — Wizard surface

| File | Change |
|---|---|
| `start.sh` | Replace existing 3-role prompt with 6-role prompt. Validate platform eligibility before showing each option. Transition-aware UX (greying out, irreversibility prompt). |
| `crates/rustynet-cli/src/operator_menu.rs` (or equivalent) | Mirror the start.sh prompt in the Rust-native menu. |
| Mobile shell hooks | iOS + Android shells display read-only "client (mobile)" role status. |

Estimated cost: 2 cycles.

### 8.4 D12.d — Service deploy / undeploy

| File | Change |
|---|---|
| `crates/rustynet-cli/src/ops_install_systemd.rs` | Extend systemd installer to optionally install `rustynet-relay.service` alongside `rustynetd.service` for relay/anchor presets. Add `--co-deploy-relay` flag. |
| `crates/rustynet-cli/src/macos_launchd.rs` (or equivalent) | Same shape for launchd `.plist` deploy on macOS. |
| `crates/rustynet-cli/src/windows_scm.rs` (or equivalent) | Same shape for Windows SCM `RustyNetRelay` service. Gated behind D7 / D9. |
| Undeploy paths | Each platform installer gets a symmetric undeploy verb that the role-transition orchestrator calls when leaving relay/anchor presets. |

Estimated cost: 3 cycles.

### 8.5 D12.e — Audit + transition logging

| File | Change |
|---|---|
| `crates/rustynet-control/src/audit.rs` (if exists; else extend membership audit log) | Every role transition (signed or local) emits a tamper-evident audit-log entry: timestamp, from-role, to-role, side-effects executed, success/failure, operator id (if available). |
| `crates/rustynetd/src/daemon.rs` | On daemon start, emit a "role resolved" audit entry capturing current preset for forensics. |
| Tests | Negative-path: failed deploy mid-transition emits audit + restores previous state. |

Estimated cost: 1 cycle.

---

## 9) Refactor inventory

What gets extended (already exists) vs net-new.

| File | Category | Reason |
|---|---|---|
| `crates/rustynetd/src/daemon.rs` | Extend | New IPC verbs, role-resolution logic combining Axis 1 + Axis 2 |
| `crates/rustynet-control/src/membership.rs` | Schema extend (append-only) | New capability flags in `NodeCapabilities` |
| `crates/rustynet-cli/src/main.rs` | Extend | Six new verbs (`role`, `capability`) |
| `crates/rustynet-cli/src/ops_install_systemd.rs` | Extend | Optional relay co-deploy |
| `start.sh` | Replace prompt | 6-role selection |
| `documents/Requirements.md` §3.7 | Replace prompt-description | Reference 6 roles instead of "select role at setup" |
| `documents/SecurityMinimumBar.md` | New §6.D | Role transition controls |
| `documents/operations/PlatformSupportMatrix.md` | Extend | Per-role eligibility matrix |
| `documents/operations/active/AnchorNodeRoleDesign_2026-05-21.md` | Cross-ref | Anchor is one of the 6 presets; defer compositional details here |
| `documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md` | New phase | D12 added to Track Alpha |
| `crates/rustynet-control/src/role_presets.rs` | New module | Preset table + transition validator |
| `crates/rustynet-cli/src/role_set.rs` | New module | Transition orchestrator |

What is NOT refactored:

- **`NodeRole` enum** stays at `Admin / Client / BlindExit`. No new variants. Axis 1 stays orthogonal to Axis 2.
- **`rustynet-relay` binary** unchanged. Role taxonomy composes it; relay binary code is untouched.
- **Existing signing flow** (assignment, DNS-zone, traversal bundles) unchanged. Role-transition records use the same flow.
- **Existing `start.sh` 3-role flow** is REPLACED, not extended, but the replacement preserves all 3 existing roles + adds 3 new ones.

---

## 10) Security controls

| Control | Enforcement | Verification |
|---|---|---|
| Role transition validated against allowed-matrix | `crates/rustynet-control/src/role_presets.rs::validate_transition` rejects blocked transitions fail-closed | Unit test: every blocked cell in §5 returns `TransitionDecision::Blocked` |
| BlindExit irreversibility | `start.sh` + `rustynet role set` refuse to switch out of `blind_exit` without explicit factory-reset flag; daemon-side double-check on apply | Test: `role set client` from `blind_exit` returns `Irreversible(factory_reset_required)` |
| Capability changes require signed membership bundle | Only Axis-1 changes (admin↔client) are local-only; Axis-2 changes always emit `MembershipUpdateRecord` for owner signing | Test: capability mutation without signature → reducer rejects |
| Service deploy precedes capability advertisement | Role-transition orchestrator deploys `rustynet-relay` BEFORE the signed bundle advertises `serves_relay` | Integration test: deploy failure → no signed bundle emitted; previous state preserved |
| Service undeploy succeeds before capability removal | Symmetric — undeploy first, then emit revocation record | Integration test: undeploy failure → revocation not emitted; alarmed |
| Audit log captures every transition | Each role/capability transition emits tamper-evident log entry | Test: failed transition + recovered transition both appear in audit log with correct ordering |
| Mobile cannot host non-client roles | Mobile FFI surface refuses `role set` to anything except `client`; mobile daemon-equivalent advertises only client capabilities | FFI smoke test on iOS + Android |
| Windows non-client roles gated behind D7/D9 | Wizard greys out blocked roles; `rustynet role set <blocked>` returns explicit "platform-blocked" error | Test: on Windows host without D7/D9 evidence, `role set anchor` fails closed |
| Cross-LAN port-mapping coordination | When transitioning to `anchor`, lex-min coordination determines whether this node takes the lease or stands down (logged either way) | Integration test: two anchors on same LAN — only lex-min requests the lease |
| Role-status read available to all primary roles | `rustynet role status` and `capability list` available to `Client` and `BlindExit` (read-only) | Test: client invocation returns status, write verbs return `permission_denied` |

---

## 11) Gates

Standard workspace gates plus three role-specific gates.

Standard:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo check --workspace --all-targets --all-features`
- `cargo test --workspace --all-targets --all-features`
- `cargo audit --deny warnings`
- `cargo deny check bans licenses sources advisories`
- `./scripts/ci/membership_gates.sh`

Role-specific (new):

- `./scripts/ci/role_taxonomy_gates.sh` (new) — runs:
  - preset table round-trip (every preset → composition → preset)
  - every transition cell in §5 matrix
  - service deploy + undeploy lifecycle on Linux (macOS smoke; Windows blocked on D7)
  - wizard prompt golden test (start.sh + operator menu emit the expected 6-option flow)
- `./scripts/ci/role_transition_audit_gates.sh` (new) — verifies every role transition emits the expected tamper-evident audit log entry; failed transitions emit failure entries; recovery emits recovery entries.
- `./scripts/ci/blind_exit_irreversibility_gates.sh` (new) — verifies every attempt to switch a `blind_exit` node to another role fails closed without factory reset.

---

## 12) Open questions

| Question | Default choice | What would re-open it |
|---|---|---|
| Should `anchor + exit` be a 7th preset? | No. Composable via `rustynet capability add serves_exit` after `role set anchor`. | If home-server-as-everything is the >50% deployment pattern in practice, promote it to a named 7th preset. |
| Should mobile present `anchor` as a future role? | No. Mobile is `client (mobile)` and that is final. | OS constraints on iOS/Android are stable; not expected to change. |
| Should `relay` imply `gossip_seed`? | No. Relay forwards traffic. Gossip seed is a separate concern. Anchor combines both because the home-server pattern wants both; pure relay deployments may not. | If pure-relay deployments routinely need gossip-seed semantics, fold into the preset. |
| Should role transitions support staged rollouts (drain peers before undeploy)? | No. Today's flow is immediate (signed revocation → next gossip cycle). | If peer disruption becomes a problem in large meshes (>50 peers), add a drain phase to the transition orchestrator. |
| Should the wizard auto-detect "this looks like a home server" and recommend `anchor`? | No. Operator picks explicitly. Heuristics for "home server" are unreliable (Pi-class hardware, residential ISP detection, etc. are all noisy signals). | If user feedback shows operators routinely picking wrong roles, add a recommendation step. |

---

## 13) Definition of done

The role taxonomy is "done" when:

- D12.a-e all land on main with passing gates.
- `rustynet role set anchor` on a clean Debian 13 install brings the host to a working anchor (relay co-deployed, capability advertised in signed membership, gossip seed priority active).
- `rustynet role set client` on the same host (admin signs the revocation) brings it back to a clean client (relay undeployed, capabilities revoked).
- `rustynet role set blind_exit` on a fresh Debian install configures hardened final-hop exit with the irreversibility prompt + audit trail.
- Wizard (start.sh + operator menu) presents all 6 roles with correct per-platform gating.
- Mobile `client (mobile)` indicator is read-only on iOS + Android.
- Documented release notes call out the role-cementation as a user-visible UX change.
- `PlatformSupportMatrix.md` per-role eligibility table reflects actual runtime truth.

---

## 14) Cross-references

- [`AnchorNodeRoleDesign_2026-05-21.md`](./AnchorNodeRoleDesign_2026-05-21.md) — detailed design for the `anchor` preset; child doc of this taxonomy.
- [`RustynetDataplaneExecutionPlan_2026-05-18.md`](./RustynetDataplaneExecutionPlan_2026-05-18.md) — D12 lands as the next Track Alpha phase after D11.
- [`../PlatformSupportMatrix.md`](../PlatformSupportMatrix.md) — per-role per-platform eligibility table.
- [`../RustynetdServiceHardening.md`](../RustynetdServiceHardening.md) — role-specific service hardening notes added in D12.
- [`../MacosLaunchdServiceManagement.md`](../MacosLaunchdServiceManagement.md) — `rustynet-relay` launchd plist for relay/anchor presets.
- [`../WindowsWorkingNodeBringUpRunbook.md`](../WindowsWorkingNodeBringUpRunbook.md) — Windows role activation gated on D7/D9.
- [`../../Requirements.md`](../../Requirements.md) — §3.7 admin/UX requirement.
- [`../../SecurityMinimumBar.md`](../../SecurityMinimumBar.md) — §6.D role transition controls.
- [`../../mobile/RustynetMobileArchitectureDesign_2026-04-17.md`](../../mobile/RustynetMobileArchitectureDesign_2026-04-17.md) — mobile is `client (mobile)` only.
