# SignedMembership Transition Signing Sub-flow: Design (+ safe skeleton) — 2026-08-27

- Date: 2026-08-27
- Status: active — design + the pure step sequencer landed on `work/d4a-signing-subflow`; the
  automated driver (who invokes signing, from where) carries owner decisions (§8) and is NOT
  implemented here. Live proof is D-4b, explicitly out of scope.
- Owner: Rustynet
- Parent docs: [`CrossOsRoleSwitchPlan_2026-06-24.md`](./CrossOsRoleSwitchPlan_2026-06-24.md) §3/§4,
  [`NodeRoleTaxonomy_2026-05-21.md`](./NodeRoleTaxonomy_2026-05-21.md) §10,
  `AGENTS.md`/`CLAUDE.md` §10.7, `SecurityMinimumBar.md` §6.D.
- Precedent followed:
  [`AnchorEnrollmentEndpointEnforcementDesign_2026-08-27.md`](./AnchorEnrollmentEndpointEnforcementDesign_2026-08-27.md)
  (D-3, on `work/d3-anchor-enrollment` at time of writing) for the design-questions +
  fail-closed-precedent shape.
- Task ID: **D-4a** — design the capability-signing sub-flow for `SignedMembership` role
  transitions.

---

## 1) The gap, verified against the code

`TransitionKind::SignedMembership` planning and local side-effect execution are **real and
platform-neutral**, not design-only:

- Planner: `crates/rustynet-cli/src/role_cli.rs:553` (`plan_concrete_actions`) — the
  SignedMembership match arms at `role_cli.rs:620-800` produce concrete ordered actions
  (`AdvertiseDefaultRoute`, `DeployExitService`, per-service deploy/undeploy, `WriteNodeRoleEnv`).
- Executor: `crates/rustynet-cli/src/main.rs:19486` (`execute_role_plan`) →
  `execute_role_action` (`main.rs:19629`) — sends the admin-gated `RouteAdvertise`/`RouteRetract`
  IPC and drives the platform service installers. Audit is fail-closed for SignedMembership
  (`finalize_role_audit`, RSA-0014, `main.rs:19598`).

What is **absent** is the signing half. After the local actions run, `role set` only prints
follow-up *instructions* (`role_cli.rs:750-760`): "Emit, sign, and apply a membership capability
update…". Nothing emits the unsigned record, nothing runs the signing session, nothing applies or
refreshes. The operator must manually chain separate commands, and no code enforces that they do,
in the right order, before relying on the new role.

### 1.1 The real manual flow (traced, with keys and custody)

The task briefing named `assignment issue` / `enrollment admit` as the manual flow to subsume.
Traced against the code, the picture is more precise — three distinct signing domains:

| Command | What it signs | Key | Custody requirement | Role in a transition |
|---|---|---|---|---|
| `membership propose-set-capabilities` (`main.rs:5889`) / `anchor advertise` (`main.rs:6142`, exec `:7488`) / `role pin-port-mapping-authority` (`main.rs:19417`) | nothing — builds the **unsigned** `SetNodeCapabilities` `MembershipUpdateRecord` (RSA-0009 rule: `preview_next_state` timestamp == record `created_at_unix`) | none | none | **the** capability-change record builder |
| `membership sign-update` (`main.rs:5940`) | the update record + head attestation | membership **approver** key (owner/guardian Ed25519), encrypted at rest, decrypted via `--signing-key-passphrase-file` (`load_signing_key`, `main.rs:16132`) | key + passphrase file live on the operator/admin station; never on the transitioning node | **the** signing step; quorum from `MembershipState.quorum_threshold` |
| `membership apply-update [--daemon]` (`main.rs:5954`) | nothing — verifies (signature → epoch/replay watermark) then applies; `--daemon` sends `IpcCommand::MembershipApply` (`ipc.rs:92`, handler `daemon.rs:8622`, **admin-role-gated**) | n/a | n/a | the publish step |
| `enrollment admit` (`main.rs:6398`, exec `:8278`) | an **AddNode** record for a *new* enrollee (token burn → build → sign → optional apply; stops at partially-signed below quorum, `main.rs:8385`) | same approver key + passphrase file, `--approver-id` | same | **not** part of a capability transition of an existing member; relevant only to `blind_exit` re-enrollment after factory reset |
| `assignment issue` (`main.rs:6267`) | the per-client tunnel **assignment bundle** (`--exit-node-id`, allow pairs, TTL, nonce) | separate **assignment signing secret** (`init-signing-secret`, ≥32B, encrypted + `--signing-secret-passphrase-file`) | operator station | follow-up when the exit set changes, so peers can select/deselect the exit (`role_cli.rs:656`, `:668`) |

Ingest on the transitioning node: `StateRefresh` IPC →
`Daemon::refresh_signed_state_with_reason` (`crates/rustynetd/src/daemon.rs:4487`) — the ONE
verified apply path (CrossOsRoleSwitchPlan §2; never fork it).

So "automate `assignment issue` / `enrollment admit` inside the transition" is directionally
right but nominally stale: the capability sub-flow composes **propose → sign-update →
apply-update → StateRefresh**, with `assignment issue` as a conditional follow-up for
exit-bearing changes and `enrollment admit` only on the irreversible path. §9 records this as a
briefing/doc staleness finding.

---

## 2) Q1 — Who signs, and where does the key live during an automated transition?

**Chosen: split-station orchestration. No key ever moves; every signing operation runs where its
key already legitimately lives; the sub-flow is driven from the admin station.**

- The membership approver key and its passphrase file are admin-station material (§1.1). The
  transitioning node performs only: local side effects (deploy/undeploy/advertise/retract),
  unsigned-record emission, and post-publish `StateRefresh`.
- The admin station performs: `membership sign-update` (non-interactively, with the existing
  encrypted-key + passphrase-file custody model — note the repo's model is **not**
  interactive prompting; every existing signing verb takes a passphrase *file*), then
  `membership apply-update` (locally or `--daemon`), then re-issues assignment bundles when the
  exit set changed (`assignment issue`, assignment secret, also admin-station).
- Degenerate case: when the transitioning node IS the admin station (self-transition of the
  admin box, e.g. admin→exit), all phases run on one host. This is the narrow "keys the
  initiating node legitimately holds" scope — allowed as a special case, not the design.
- Quorum: if `quorum_threshold > 1`, the sub-flow stops after its own signature with a
  partially-signed artifact and reports the exact `sign-update --merge-from` chain needed —
  the same terminal state `enrollment admit` already implements (`main.rs:8385`).
  **Multi-approver signature collection is out of scope for automation.**

Rejected alternatives:

- **Prompt for the owner passphrase at transition time on the transitioning node.** Requires the
  approver key on that node → key movement, violating §4 custody and the §6.C "a node is not a
  trust authority" boundary. Also contradicts the repo's passphrase-file (non-interactive)
  custody model.
- **Pre-issued signed artifact as the primary mode** (owner signs the capability update before
  the transition starts, node consumes it). Rejected because it inverts §10.7: a signed
  advertisement would exist before the service is deployed/healthy; if it leaks or is applied
  early, the published-capability-precedes-running-service invariant breaks. A signed artifact
  is acceptable only *after* the local phase completes (it is exactly what resumability stores,
  §5) — never before.
- **Copy the approver key to the transitioning node under encryption.** Flatly out: strict key
  custody (§4), and the D-3 precedent's trust-boundary reasoning.

Out of scope (stated per the task): new crypto or signature formats (none introduced — the
sub-flow is pure composition of the §1.1 verbs), multi-approver automation, remote
signing-service/HSM integration, and the live flip itself (D-4b).

## 3) Q2 — Ordering: the §10.7 problem, generalized

Invariants (the two directions of the same rule):

- **I-1 (add):** a published capability must never precede its running, healthy service.
- **I-2 (remove):** a revoked capability must never leave its service (or exit NAT/forwarding)
  running — residue is a release-blocking defect (SecurityMinimumBar §6.D control 7).

Per-capability side-effect table and order:

| Capability | Side effect | ADD order | REMOVE order |
|---|---|---|---|
| `serves_relay`, `serves_nas`, `serves_llm`, `anchor.relay_colocation` (capability-providing sibling services) | install/run `rustynet-relay` / `rustynet-nas` / `rustynet-llm-gateway` | deploy + verify healthy → emit → sign → publish | undeploy → emit revocation → sign → publish |
| `serves_exit` | NAT/forwarding via admin-gated `RouteAdvertise 0.0.0.0/0` + platform preflight unit | **advertise route → deploy preflight** → emit → sign → publish (the advertise IPC IS the atomic bring-up + ownership signal — the documented inversion at `role_cli.rs:637-651`; I-1 is satisfied because the *route advertisement inside signed assignment state* is the bring-up, and the membership capability publishes after) | undeploy preflight → retract route → emit revocation → sign → publish (strict §10.7) |
| `anchor.gossip_seed`, `anchor.bundle_pull`, `anchor.enrollment_endpoint`, `anchor.port_mapping_authoritative` | no separate deployable service — daemon-internal listeners with **per-request serve-side capability gates** (`daemon.rs:1323` bundle-pull; D-3 for enrollment_endpoint) | no local deploy step; emit → sign → publish; the serve gates activate on the node's own snapshot refresh | emit revocation → sign → publish; serve gates refuse from the next request after refresh |
| primary-role change riding along | env/plist/service-config rewrite + daemon restart | first, before everything (matches `role_cli` generic arm) | same |

Canonical full sequence (what the landed sequencer encodes):

```
[UpdatePrimaryRoleConfig]                      (iff primary changes)
[AdvertiseExitRoute → DeployExitPreflight]     (iff adds serves_exit)
[DeployService(k)...]                          (canonical ServiceKind order)
[UndeployService(k)...]                        (deploys precede undeploys: new service up before old goes down)
[UndeployExitPreflight → RetractExitRoute]     (iff removes serves_exit)
EmitUnsignedCapabilityRecord
CollectApproverSignatures                      (external; admin-station; stops below quorum)
PublishSignedUpdate                            (verify → watermark → apply)
RefreshSignedState                             (StateRefresh on the transitioning node)
```

One signed `SetNodeCapabilities` record covers the whole delta (mixed add+remove transitions,
e.g. nas→relay, publish atomically — both services' lifecycle steps precede the single emission,
so both invariants hold at the single publish point).

## 4) Q3 — Partial failure at every step boundary

Fail-closed rule inherited from D-3: peers trust only the quorum-signed roster, and serve-side
gates re-check per request — so every intermediate state below is safe against *wrongly served
trust*; the only windows are availability windows.

| Process dies… | Node state | Safe? Why | Recovery | Operator visibility |
|---|---|---|---|---|
| during `UpdatePrimaryRoleConfig` | env/plist rewrite is atomic (`update_node_role_env_file` / `update_node_role_macos_plist`) | yes — old or new file, never torn | idempotent re-run | `role status`; audit log |
| after `AdvertiseExitRoute`, before preflight | NAT up, preflight absent, capability unpublished | yes — no peer can select it: capability not in signed membership, no assignment names it as exit | re-run (advertise is idempotent IPC); rollback = `RouteRetract` | `role status` + route list |
| after deploys, before emit | services running, capability unpublished | yes — unpublished ⇒ unselected; anchor-style gates refuse anyway | re-run; installers converge (install+enable are idempotent) | service status; audit log |
| after emit, before sign | unsigned record file on disk | yes — unsigned = inert; record carries `expires_at_unix` and binds `prev_state_root`/`epoch_prev`, so a stale one **fails apply cleanly** (RSA-0009) | re-run regenerates from current state; stale file harmless | record file + summary output |
| after sign, before publish | signed artifact on admin station, below-or-at quorum | yes — artifact is bounded by TTL; replay watermark prevents double-apply later | resume: publish it; or let it expire and re-run from emit | `membership verify-update --dry-run` |
| after publish, before full distribution / `RefreshSignedState` | roster updated at the apply point; gossip/bundle-pull converging | yes — epoch is monotonic; nodes converge via the verified pull path; the transitioning node serves per its *local* snapshot, which the serve gates re-read per request | `StateRefresh` (idempotent); normal reconcile | `membership status`; run matrix |
| **remove path:** after undeploy/retract, before revocation publishes | service down / NAT torn, capability **still published** | yes for security (nothing serves; exit peers fail closed via route retract on next reconcile, per `role_cli.rs:662-668`), **no for availability** — peers may still select a dead relay/exit until publish | resume to emit→sign→publish; this window is why the sub-flow must be resumable, not abandonable | audit log shows Succeeded local phase without a matching publish |
| undeploy **fails** (not dies) | service still up, capability still published | yes — sub-flow aborts **before** emission ⇒ fully consistent old state; matches Taxonomy §10 "undeploy failure → revocation not emitted; alarmed" | fix, re-run | `Failed` audit entry (fail-closed for SignedMembership, RSA-0014) |

The inverse of the remove-path window — revoked-but-still-running — **cannot occur by
construction**: undeploy/retract strictly precede revocation emission, and an undeploy failure
aborts before emission. That is I-2 enforced by ordering, not by cleanup.

## 5) Q4 — Idempotency + resumability

Yes, by re-run-from-start with convergent steps (chosen over checkpoint files):

- Pure planner + sequencer: recomputing the plan from `role status` + membership state yields
  the same remaining work; already-done steps are no-ops (idempotent installers, idempotent
  route IPC, duplicate-detection in the reducer).
- The only non-idempotent-looking step, publish, is protected by the epoch/replay watermark: a
  second apply of the same update fails cleanly; a regenerated record binds the *new*
  `prev_state_root` so it either applies once or rejects.
- The signed artifact between sign and publish is the one resumable checkpoint, bounded by the
  record TTL. Below-quorum artifacts resume via `sign-update --merge-from` (existing).
- No rollback orchestration: rollback of an interrupted ADD is itself a REMOVE-direction
  sub-flow (and vice versa) — compose, don't special-case. Refuse-and-report happens at: audit
  append failure (RSA-0014, already fail-closed), deploy/undeploy failure, quorum shortfall,
  verify/apply failure.

## 6) What was implemented (safe skeleton only)

- `crates/rustynet-control/src/role_signing_subflow.rs` — NEW: pure `SubflowStep` sequencer
  (`signing_subflow_steps` / `signing_subflow_for`), fail-closed on non-SignedMembership kinds,
  with 9 unit tests proving: every deploy precedes emission; every undeploy precedes emission;
  emit → sign → publish → refresh order with refresh terminal; the exit ADD inversion
  (advertise before preflight); the exit REMOVE strict order; deploys before undeploys;
  relay lifecycle both directions; primary-change step first; non-SignedMembership rejection.
- `crates/rustynet-cli/src/role_cli.rs` — NEW contract test
  `signing_subflow_local_phase_matches_concrete_action_order`: for every non-staged
  SignedMembership cell in the 8×8 preset matrix, the sequencer's local phase equals the
  planner's executable `ConcreteAction` order — the two encodings cannot silently diverge.
- No real signing, no IPC, no I/O, no new CLI verbs, no daemon changes. `CollectApproverSignatures`
  is deliberately abstract so the sequencer does not prejudge §8's owner decisions.

## 7) Rejected design alternatives (beyond §2's)

- **Sequencer inside `role_cli::plan_concrete_actions` itself** (extend `ConcreteAction` with
  Emit/Sign/Publish variants): rejected — `execute_role_action` executes every action in-process
  on the transitioning node, and signing steps must NOT be executable there (§2). Separate
  vocabulary + contract test keeps the boundary type-visible.
- **Encode "verify healthy" as a distinct step now:** folded into `DeployService`'s doc contract
  instead; what "healthy" means per service is an owner decision (§8.3) and a wrong guess here
  would bake into the step vocabulary.
- **Auto-apply on the signing station when quorum met, always** (`enrollment admit --apply`
  shape): kept as the driver's likely default but not encoded in the sequencer; publish target
  (local files vs `--daemon`) is deployment-specific.

## 8) Needs owner sign-off

1. **Driver placement:** admin-station CLI one-shot (`rustynet role transition-drive`-style) vs
   live-lab-stage-only automation first. The design assumes the split-station model either way.
2. **Quorum > 1:** confirm multi-approver signature collection stays manual
   (`sign-update --merge-from`), with the sub-flow terminating at partially-signed.
3. **Per-service health checks:** what "deployed and healthy" must verify for relay/nas/llm
   before emission (unit active? port bound? self-probe?). Blocks encoding a `VerifyServiceHealthy`
   step.
4. **Remove-path availability window** (§4 row 7): accept + document (recommended, matches
   §10.7), or add a drain/re-issue-assignments step before undeploy for exit specifically.
5. **Signed-artifact TTL policy** for the sign→publish checkpoint (default record TTL vs a
   tighter transition-specific TTL).
6. **Should `role set` start emitting the unsigned record itself** (upgrading follow-up text to
   an artifact)? Touches the operator UX and the audit story; cheap, but changes a shipped verb.

## 9) Stale facts found (and what was corrected)

1. **`CrossOsRoleSwitchPlan_2026-06-24.md` status blockquote**: claimed the SignedMembership
   kind "remains design-only for both OS". Wrong in one direction — the planner + concrete-action
   executor + audit fail-close are implemented and platform-neutral (§1 evidence); what is
   absent is the signing sub-flow automation and live proof. Corrected in-place with a dated
   note (mirroring the substrate spec's §0.5 pattern).
2. **Task-briefing framing** "the manual flow = `assignment issue` / `enrollment admit`":
   `enrollment admit` is new-node admission, not capability change; the operative manual chain
   is propose-set-capabilities/anchor-advertise → sign-update → apply-update (+ conditional
   `assignment issue` for exit changes). §1.1.
3. **Merge-overlap note:** `documents/README.md` and `documents/operations/active/README.md`
   index lists were also touched by the unmerged `work/d3-anchor-enrollment` branch (its
   `AnchorEnrollmentEndpointEnforcementDesign_2026-08-27.md` entries sit in the same list
   regions as this doc's). Expect a trivial adjacent-line merge conflict; both entries should
   survive.

## 10) Code anchors

- Sequencer: `crates/rustynet-control/src/role_signing_subflow.rs`; contract test:
  `crates/rustynet-cli/src/role_cli.rs` (tests module, `signing_subflow_local_phase_matches_concrete_action_order`).
- Planner/executor: `role_cli.rs:553`, `main.rs:19482`, `main.rs:19629`.
- Signing verbs: `main.rs:5889/5940/5954/6142/6267/6398`, `load_signing_key` `main.rs:16132`.
- Verified apply path: `daemon.rs:4487`; `MembershipApply` handler `daemon.rs:8622`; serve-side
  gate precedent `daemon.rs:1323` + D-3 doc.
- Ordering decree: `AGENTS.md` §10.7; `NodeRoleTaxonomy_2026-05-21.md` §10;
  `SecurityMinimumBar.md` §6.D control 7.
