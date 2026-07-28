# Rustynet Repo Context Prompt

> Purpose: load full repo context into a fresh agent session fast — what this project is,
> its non-negotiable constraints, its security model, its documentation map, its crate
> architecture, its key domain types, and the engineering patterns that pass review here.
> This doc is NOT task-specific and NOT the live-lab operating loop — for driving live-lab
> runs, read the companion doc **`rustynet_live_lab_loop_prompt.md`** instead (it assumes
> you have already internalised this one). This doc is reference, not rules-with-teeth —
> `AGENTS.md`/`CLAUDE.md` remain the authoritative operating contract; this reorganizes and
> extends that material (plus `documents/CODE_MAP.md`, the doc indexes, and file:line
> specifics) into one consolidated read. Update this doc when the project's architecture,
> crate layout, or doc structure changes — not when a specific bug or ledger status changes.
>
> **Verified against the code 2026-07-27** (adversarial pass; every ✅, every file:line, every
> command, and every MCP tool signature re-checked against committed code, with the documented
> `xtask` commands actually executed). Corrections landed in §2, §4, §5, §6, §7, §8, §10, §11,
> §12, §13, §14, §15, §16, §17. If you find a claim here that the code contradicts, fix the
> claim in the same change — this file's only job is to be true today, so a stale line in it is
> worse than a missing one.

═══════════════════════════════════════════
1) MISSION & SCOPE
═══════════════════════════════════════════
Rustynet is a production-grade, security-first Rust mesh VPN — a Cargo workspace
(`edition = "2024"`, `resolver = "2"`, and `unsafe_code = "forbid"` declared in
`[workspace.lints.rust]`). The forbid is inherited by every crate carrying `[lints] workspace =
true`, which is all of them except three documented cases: `rustynetd` downgrades it to
`deny` at the manifest level so one scoped `#[allow(unsafe_code)]` module
(`macos_utun_helper_unsafe`, the SCM_RIGHTS fd-passing primitives) can compile — every other
`rustynetd` module still pins `#![forbid(unsafe_code)]` per file; `rustynet-windows-native`
does not inherit the workspace lints at all and legitimately contains ~94 `unsafe` blocks
(Win32 FFI — the sanctioned OS-boundary exception); `rustynet-lab-monitor` is outside the
workspace entirely. Do NOT assume "no unsafe anywhere". It is being
built to the same bar as Tailscale/NetBird-class overlay networks: signed membership state,
default-deny policy, fail-closed trust handling, WireGuard behind a replaceable backend
adapter, no custom cryptography, no custom VPN protocol.

Priorities, in order: **security first, then correctness, then everything else.** Prefer
code, tests, gates, and live-lab evidence over design-only churn. A feature is not "done"
because it compiles — it is done when it is live-lab-proven and every security control it
touches has an enforcement point plus a verification test.

═══════════════════════════════════════════
2) NON-NEGOTIABLE ENGINEERING CONSTRAINTS
═══════════════════════════════════════════
These override any other instinct, convenience, or shortcut:

- **Rust-first.** Non-Rust code only for unavoidable OS integration boundaries (the
  `rustynet-windows-native` crate is the sanctioned exception — WFP/DPAPI/named pipes).
- **No custom cryptography and no custom VPN protocol invention** in production paths.
- **WireGuard is an adapter, not a foundation.** It sits behind `rustynet-backend-api`'s
  stable trait; domain crates must never see a WireGuard type.
- **No WireGuard-specific leakage** into protocol-agnostic control, policy, or domain crates.
- **Default-deny is mandatory** across ACL, routes, and trust-sensitive flows. Empty/missing/
  malformed input → deny, never allow.
- **Fail closed** when trust/security state is missing, invalid, stale, or unavailable. Never
  default to a permissive fallback.
- **No TODO/FIXME/placeholder deferrals** in completed deliverables.
- **One hardened execution path per security-sensitive workflow.** No runtime fallback,
  downgrade, or legacy branch in a production security path.

═══════════════════════════════════════════
3) SECURITY BASELINE REQUIREMENTS
═══════════════════════════════════════════
- Signed control/trust state must be validated **before** mutation — verify signature, then
  epoch/replay-watermark, then apply. Never apply unsigned or stale state.
- Anti-replay and rollback protection wherever state freshness matters.
- Strict key custody: OS-secure storage (Keychain/DPAPI) when available, otherwise
  encrypted-at-rest with strict permissions and startup permission checks.
- Never log secrets or private key material — no `Debug`-printing a type holding key material
  unless its `Debug` impl explicitly redacts.
- Privileged-boundary hardening: argv-only exec for helpers, strict input validation, no shell
  construction with untrusted values.
- Tunnel and DNS fail-closed behavior must be preserved in protected modes.
- During the ongoing shell-to-Rust migration, superseded shell implementations must be removed
  from active paths; any remaining wrapper may only dispatch to the Rust command and must fail
  closed on error.

**Every implemented security control needs two things: (1) an enforcement point in code, (2) a
verification method** (unit test, integration test, negative test, or gate check). See §8 for
the current control catalog with both columns filled in.

═══════════════════════════════════════════
4) READ ORDER & DOCUMENTATION MAP
═══════════════════════════════════════════
**Precedence when documents disagree** (highest first):
1. `documents/Requirements.md`
2. `documents/SecurityMinimumBar.md`
3. The active scope document for the task at hand
4. Supporting design docs
5. `README.md` and operational runbooks

**Read in this order before touching code:**
1. `AGENTS.md` / `CLAUDE.md` (byte-for-byte mirrored operating contract)
2. `README.md` (repo root)
3. `documents/README.md` (top-level docs map)
4. `documents/Requirements.md`
5. `documents/SecurityMinimumBar.md`
6. The active scope document for the task
7. Relevant runbooks under `documents/operations/`

**The docs tree is large (310 files as of 2026-07-27, per `list_documents`) and actively curated
— don't hand-enumerate it, use the tools built for it:**
- `mcp__rustynet-repo-context__get_read_order(task)` — hands you the exact ordered doc list for
  a described task (e.g. "add a relay feature", "fix a Windows killswitch bug").
- `mcp__rustynet-repo-context__list_documents(filter?)` — every `.md` in the repo, grouped by
  directory, with title + line count. The ground truth for "does this doc exist."
- `mcp__rustynet-repo-context__get_active_ledger(topic)` — given a topic keyword (traversal,
  relay, enrollment, gossip, anchor, roles, exit, windows, macos, orchestrator, security,
  killswitch, dns, testing, migration, vm, lab, dependencies, privacy), returns the ledger(s)
  that own it, with status.
- `mcp__rustynet-repo-context__find_in_docs(query)` — full-text search across the entire docs
  tree.

**Structure, so you know where to look:**
- `documents/` root — normative docs (`Requirements.md`, `SecurityMinimumBar.md`,
  `CODE_MAP.md`) and phase/architecture history (`Phase1.md`...`Phase6.md`, `phase10.md`;
  Phase 7-9 are archived as future commercial-roadmap material with no current implementation
  work).
- `documents/operations/` — evergreen runbooks, policies, matrices, gate references (start at
  `operations/README.md`).
- `documents/operations/active/` — **the current execution surface.** Every in-flight ledger,
  plan, backlog, and audit lives here; `active/README.md` is the canonical index and is kept
  current in the same commit as any doc move (own it: read it fresh every session, don't trust
  a stale mental model). The single most useful entry points as of this writing:
  `RustynetUnifiedTodoLedger_*` (repo-wide TODO roll-up), `CrossPlatformRoleParityPlan_*`
  (release-blocking per-role × OS live-proof matrix), `LiveLabExecutionEfficiencyPlan_*` (the
  loop method), `SecurityAuditLedger_*` / `SecurityRemediationPlan_*` (the standing security
  backlog).
- `documents/operations/done/` — historical evidence, not current operating guidance.
- `documents/operations/adr/` — Architecture Decision Records, immutable once accepted.
- `documents/archive/` — retired phase/security-review material; re-validate against present
  code before treating as current.
- `documents/mobile/` — forward-looking mobile-client architecture/roadmap, not yet active
  implementation.

**Documentation hygiene rules that bind every agent** (see §12 for the full list): if you add,
remove, rename, or repurpose a doc, update the owning index in the *same* change. Do not create
a new standalone prompt/status document — put execution guidance in the owning active ledger.
`AGENTS.md` and `CLAUDE.md` are intentionally byte-for-byte mirrored; any edit to one applies
identically to the other in the same change.

═══════════════════════════════════════════
5) REPOSITORY LAYOUT
═══════════════════════════════════════════
- `crates/` — every workspace crate (§6).
- `third_party/` — vendored path deps treated as adapters behind the backend boundary, never
  leaked upward: `boringtun` (userspace WireGuard), `rustynet-tun` (TUN device),
  `rustynet-alloc-meter` (allocation accounting).
- `documents/` — source-of-truth docs (§4).
- `scripts/` — operational + CI tooling by area: `ci/` (gate scripts, many thin wrappers over a
  Rust binary of the same name in `rustynet-cli/src/bin/` — the Rust binary is the real
  implementation per the shell-to-Rust migration rule), `vm_lab/` (UTM lab helpers incl.
  `probe_and_recover_local_utm.sh`), `bootstrap/`, `dev/`, `e2e/`, `fuzz/`, `launchd/`,
  `systemd/`, `windows/`, `perf/`, `release/`, `operations/`, `mcp/`, `loop/` (the
  operator-driven autonomous-loop runner scripts).
- `fuzz/` — `cargo-fuzz` targets (`ipc_parse_command`, `membership_decode_state`,
  `membership_decode_signed_update`); its own `[workspace]`.
- `mcp/` (`mcp.json`) and `tools/skills/` — MCP server config and the
  `rustynet-security-auditor` skill (attack catalog, audit checklist, lab playbooks).
- `profiles/live_lab/` — live-lab impairment/topology profiles.
- `artifacts/` — generated evidence/SBOM/provenance outputs — do not hand-edit.
- `gui/node-map-tool/` — tracked operator-side UI tool with its OWN workspace + `Cargo.lock`,
  deliberately `exclude`d from the security-gated workspace (UI dependency trees / license
  surface). Not covered by `--workspace` gates. Same treatment as
  `crates/rustynet-lab-monitor/`.
- `bin/` — **gitignored** drop point for prebuilt MCP server binaries
  (`rustynet-mcp-{repo-context,gate-runner,lab-state,ai-agent}`) that `mcp/mcp.json` launches.
  `scripts/ci/check_mcp_binaries_fresh.sh` fails loud when one is stale — rebuild rather than
  debugging a stale server's answers.
- `state/` — gitignored live-lab runtime scratch (run logs, known_hosts, profiles). Never source
  of truth, never cite it as evidence.
- `start.sh` — interactive setup/menu wizard. `rust-toolchain.toml` pins the toolchain.
  `deny.toml` configures `cargo deny`.

═══════════════════════════════════════════
6) WORKSPACE CRATE MAP — ARCHITECTURAL LAYERS
═══════════════════════════════════════════
For a symbol-level reference (key types, traits, functions, and where they live), read
`documents/CODE_MAP.md` — the authoritative code map, kept in sync when types move. This
section is the layer-level orientation.

**Domain layer** (transport-agnostic — never import a backend or WireGuard type here):
| Crate | Owns |
|---|---|
| `rustynet-control` | Membership bundles, enrollment tokens, roles/capabilities, role transitions, gossip, replay watermarks. The core trust-state crate. |
| `rustynet-policy` | ACL + policy evaluation — default-deny always. |
| `rustynet-dns-zone` | Magic DNS signed-zone schema. |
| `rustynet-crypto` | Signing, key types, key custody primitives. |
| `rustynet-local-security` | Local ACL verifiers / privileged-boundary checks. |
| `rustynet-sysinfo` | OS detection, interface enumeration. |

**Daemon + services layer:**
| Crate (binary) | Does |
|---|---|
| `rustynetd` | The node daemon: WireGuard management, dataplane engine, STUN, gossip runtime/transport, ICE, enrollment, killswitch. |
| `rustynet-relay` | Frame forwarding for the zero-ingress relay role. |
| `rustynet-nas` | `nas` service-hosting role (tunnel-only storage). |
| `rustynet-llm-gateway` | `llm` service-hosting role (identity-from-tunnel gateway in front of a loopback inference engine). |

**Backend abstraction layer** (the WireGuard adapter boundary):
| Crate | Owns |
|---|---|
| `rustynet-backend-api` | The `TunnelBackend` trait (`src/lib.rs:198` — NOT named `Backend`) and abstract types. No backend internals. |
| `rustynet-backend-wireguard` | The one production WireGuard adapter crate, holding BOTH the kernel-path command adapters (`linux-wireguard`, `macos-wireguard`, `windows-wireguard-nt`) and the boringtun userspace-shared backends (`LinuxUserspaceSharedBackend`, `MacosUserspaceSharedBackend`). Wraps vendored `boringtun` + `rustynet-tun`. This is the crate `rustynetd` actually depends on for every platform. |
| `rustynet-backend-userspace` | A 228-line re-export shim: `UserspaceBackend` delegates to `rustynet-backend-wireguard`'s `{Linux,Macos}UserspaceSharedBackend`. **No workspace crate depends on it** — `rustynetd` reaches the shared backends directly. Do not assume the macOS userspace dataplane flows through here. |
| `rustynet-backend-stub` | Deterministic test stub backend. **No workspace crate depends on it** either; it exists for backend-contract conformance tests. |

**Platform + UX + tooling layer:**
| Crate | Does |
|---|---|
| `rustynet-windows-native` | Windows-specific integration (WFP, DPAPI, named pipes) — the sanctioned OS-boundary exception to Rust-first purity. |
| `rustynet-operator` | Operator wizards/config (`rustynet operator menu`). |
| `rustynet-advisor` | FIS-0005 role-placement decision support: pure MCDA scorer over per-candidate observations (`rustynet role recommend`). Domain layer; collectors live in the CLI. |
| `rustynet-cli` | The main `rustynet` binary (`default-run = "rustynet-cli"`): `ops`, role/anchor/llm subcommands. **The lab robot — `vm-lab`, the live-lab orchestrator, and the e2e/cross-network/fresh-install `ops` surface — compiles only under the DEFAULT-OFF `vm-lab` cargo feature** (RNQ-17): the shipped release binary carries none of it, CI gates run `--all-features`, lab hosts/guests build with `--features vm-lab`. `src/bin/` also holds the large family of `live_*`, `*_gates`, `phase*`, `check_*` evidence/gate binaries the `scripts/ci/` wrappers dispatch to. |
| `rustynet-mcp` | MCP servers: `rustynet-mcp-repo-context`, `rustynet-mcp-gate-runner`, `rustynet-mcp-lab-state`, `rustynet-mcp-ai-agent`. |
| `rustynet-xtask` | The `xtask` dev runner (§10). |
| `rustynet-netns-probe` | LAB TOOLING (not shipped): the Rust-native STUN responder + NAT mapping/filtering probes the `--node` cross-network netns simulator runs on-guest. `std`-only, offline-buildable. STUN wire is byte-pinned to `rustynetd`'s `stun_client.rs`. |
| `rustynet-lab-monitor` | The pixelated TUI live-lab monitor. Excluded from the main workspace; build separately. |

**Dependency chains** — exact reverse-dependency sets, read out of `crates/*/Cargo.toml`
(who breaks when you patch the shared crate):
- `rustynet-control` ← `rustynetd`, `rustynet-cli`, `rustynet-relay`. (NOT `rustynet-operator`
  and NOT `rustynet-mcp` — neither depends on any internal crate.)
- `rustynet-policy` ← `rustynetd`, `rustynet-control`, `rustynet-cli`, `rustynet-llm-gateway`.
  Policy eval is NOT daemon-only: `rustynet-control` and the LLM gateway both link it.
- `rustynet-crypto` ← `rustynet-control`, `rustynetd`, `rustynet-cli`, `rustynet-nas`.
- `rustynet-backend-api` ← `rustynet-backend-{wireguard,userspace,stub}`; but only
  `rustynet-backend-api` + `rustynet-backend-wireguard` are consumed by `rustynetd`.
  `backend-userspace` and `backend-stub` have no workspace consumers at all.
- `rustynet-windows-native` ← `rustynetd`, `rustynet-control`, `rustynet-crypto`,
  `rustynet-relay`, `rustynet-backend-wireguard` (mostly under `[target.'cfg(windows)']`).
  Note `rustynet-cli` does NOT depend on it directly.
- `rustynet-cli` ← nothing (top of the graph); it depends on almost everything, so it is the
  crate most often broken by a domain-crate API change.

**CRITICAL BOUNDARY:** domain crates (`control`, `policy`, `dns-zone`, `crypto`) MUST NOT import
backend or WireGuard types. The backend trait (`TunnelBackend`) lives in
`rustynet-backend-api`; all WireGuard-specific code lives behind it. Violation is blocked by
`scripts/ci/check_backend_boundary_leakage.sh` (a 2-line wrapper that `exec`s
`cargo run -p rustynet-cli --bin check_backend_boundary_leakage`).

**Release profile note:** `[profile.release]`/`[profile.bench]` enable thin LTO and pin
`codegen-units = 1` for the hot crypto/dataplane crates (`boringtun`,
`rustynet-backend-wireguard`, `rustynet-relay`) — a perf tuning, keep it only while the
perfprobe/criterion numbers justify the build-time cost.

Tool caveats, verified by calling them — do not treat these three as "always fresh":
- `get_crate_structure()` returns a **hand-maintained static list of 17 crates** compiled into
  `crates/rustynet-mcp/src/bin/repo_context.rs` (`static CRATES`, ~line 1888). It is missing
  `rustynet-nas`, `rustynet-llm-gateway`, `rustynet-advisor`, `rustynet-netns-probe`, and
  `rustynet-lab-monitor`. The table above is more complete than the tool.
- `get_crate_dependencies(crate)` **requires a crate name** and IS parsed live from
  `crates/*/Cargo.toml` — this one is trustworthy. Call it as
  `get_crate_dependencies(crate: "rustynet-backend-api")`.
- `which_crate(path)` takes a **repo-relative FILE PATH**, not a symbol or concept. It looks for
  a literal `crates/<name>/` segment. `which_crate("MembershipState")` returns
  "No owning crate" — verified. To go from a symbol to its crate, grep, or use `find_in_docs` /
  `documents/CODE_MAP.md`.

═══════════════════════════════════════════
7) KEY DOMAIN TYPES & ROLE TRANSITIONS
═══════════════════════════════════════════
Exact type names and file:line, verified against the code. Several of these do NOT have the
obvious name — use the real one or your grep will come up empty.

| Type | File:line | Notes |
|---|---|---|
| `RolePreset` (Client/Admin/Exit/BlindExit/Relay/Anchor/Nas/Llm) | `rustynet-control/src/role_presets.rs:34` | **This** is the canonical 8-role user-facing enum. |
| `PrimaryRole` (Admin/Client/BlindExit) | `rustynet-control/src/role_presets.rs:134` | The local primary role a preset maps down to. |
| `Capability` enum | `rustynet-control/src/role_presets.rs:178` | Preset-composition capabilities: `ServesExit`, `ServesRelay`, `AnchorGossipSeed`, `AnchorBundlePull`, `AnchorEnrollmentEndpoint`, `AnchorRelayColocation`, `AnchorPortMappingAuthoritative`, `ServesNas`/`ServesLlm`. Operational metadata, NOT trust authority. |
| `RoleCapability` enum | `rustynet-control/src/roles.rs:6` | A *second*, distinct enum — the membership-wire capability that enters the canonical signed pre-image (`Anchor`, `Client`, `ExitServer`, `BlindExit`, `RelayHost`, `EntryRelay`, `Anchor*`). **Append-only: reordering variants changes the signed pre-image.** `roles.rs` contains NO role enum, only this + `ANCHOR_CAPABILITIES`. |
| `TransitionPlan` / `TransitionKind` | `rustynet-control/src/role_presets.rs:472` / `:429` | The transition plan + its outcome kind: `Identity`/`LocalOnly`/`SignedMembership`/`Blocked(reason)`/`Irreversible(reason)`. There is no type named `RoleTransition`. |
| `MembershipState` | `rustynet-control/src/membership.rs:175` | Signed membership bundle, peer list, epoch, watermark. |
| `MembershipOperation` (enum) | `rustynet-control/src/membership.rs:373` | `AddNode`/`RemoveNode`/`RevokeNode`/`RestoreNode`/`RotateNodeKey`/`SetNodeCapabilities`/`RotateApprover`/`SetQuorum`. There is no type named `SignedUpdate`. |
| `SignedMembershipUpdate` | `rustynet-control/src/membership.rs:581` | The signed wrapper an operation travels in. |
| `PolicySet` / `ContextualPolicySet` | `rustynet-policy/src/lib.rs:126` / `:195` | The default-deny ACL evaluators (`evaluate`, `evaluate_with_membership`) — both fall through to `Decision::Deny`. There is no `eval.rs` and no `DefaultDenyPolicy`; `rustynet-policy` is a single `lib.rs`. |
| `TunnelBackend` trait | `rustynet-backend-api/src/lib.rs:198` | Tunnel backend abstraction — WireGuard lives behind it. Not named `Backend`. |

**Beware three unrelated `NodeRole` enums.** None of them lives in `rustynet-control`:
`rustynetd/src/daemon.rs:1384` (daemon role), `rustynet-cli/src/vm_lab/orchestrator/role.rs:12`
(lab-orchestrator role, includes `Entry`/`Aux`/`Extra`/`Custom`), and
`rustynet-operator/src/role.rs:5` (operator/host role). If a task says "the role enum", pin down
which layer first — the domain-layer one is `RolePreset`.

**Role transitions are not just string changes — the side effects matter more than the role
field.** Rules (verify against `mcp__rustynet-repo-context__get_role_transition(from, to,
platform?)` — both `from` and `to` are REQUIRED, a no-arg call errors — or read
`rustynet-control/src/role_presets.rs` before writing any role-transition code):
- client→admin: signed, adds `serves_admin`
- admin→exit: signed, adds `serves_exit` (also deploys the relay service if `serves_relay`)
- exit→blind_exit: signed, **IRREVERSIBLE** (requires factory reset)
- blind_exit→anything: **BLOCKED by design**
- client→relay: signed, adds `serves_relay` (deploys the `rustynet-relay` service)
- anything→anchor: signed, needs an existing anchor already in the mesh
- **Adding `serves_relay`: deploy the service BEFORE emitting the signed bundle.**
- **Removing `serves_relay`: undeploy the service BEFORE the revocation bundle.**
- **Exit NAT teardown MUST happen BEFORE removing the exit capability** — residue is a
  release-blocker.
- Every transition emits an append-only audit log entry.

═══════════════════════════════════════════
8) SECURITY CONTROLS CATALOG (from `SecurityMinimumBar.md`)
═══════════════════════════════════════════
Controls to preserve in every patch — non-negotiable. The enforcement-point column is the file
you patch when a control breaks; the verifier column is what proves it (unit test or live-lab
stage). Both must exist before a control counts as "done."

| § | Control | Enforcement point | Verifier |
|---|---|---|---|
| 4.A | Signed state validation before mutation | `rustynet-control/src/membership.rs:910` — `apply_signed_update()` runs `state.validate()`, network-id/expiry/skew/prev-state-root/epoch-chain checks, then `verify_membership_signatures()` (`:938`), and only then reduces. There is no `verify()`/`apply()` pair to grep for. | unit test + live lab |
| 4.B | Anti-replay watermark | `rustynet-control/src/membership.rs:1413` `membership_watermark_is_replay()`, `:1426` `load_membership_watermark()`, `:1816` `verify_epoch_tagged_bundle()`; per-epoch policy in `rustynet-control/src/key_rotation.rs` (`PerEpochReplayWatermark`). **There is no `watermark.rs`.** | unit test |
| 4.C | Key custody: OS secure storage or encrypted-at-rest | `rustynet-crypto/src/lib.rs:311`/`:331` (`store_in_macos_keychain`/`load_from_macos_keychain`, `SecKeychain` at `:21`) + `validate_key_custody_permissions`; per-OS enforcement in `rustynetd/src/{linux,macos,windows}_key_custody.rs` (`0o600` at `linux_key_custody.rs:183`). **There is no `rustynet-crypto/src/key_custody.rs`** — that crate is a single `lib.rs`. | key_custody stage |
| 4.D | No secrets in logs | `rustynetd/src/secret_log_audit.rs` — greps the daemon journal for key material | secrets_not_in_logs stage |
| 4.E | Default-deny ACL | `rustynet-policy/src/lib.rs:131` `PolicySet::evaluate` and `:152` `evaluate_with_membership` — no matching rule falls through to `Decision::Deny`. **There is no `eval.rs`.** | policy_default_deny audit |
| 4.F | Fail-closed on trust state unavailable | `rustynetd/src/phase10.rs` — error on missing state, never default | runtime validation |
| 4.G | One hardened execution path, no runtime fallback | all security paths — no try-or-downgrade | code review |
| 4.H | Privileged helper argv allowlist | `rustynetd/src/privileged_helper.rs` — `validate_request()` | helper_allowlist audit |
| 4.I | `blind_exit` irreversibility | `rustynet-control/src/role_presets.rs:537-545` — leaving `RolePreset::BlindExit` returns `TransitionKind::Blocked("blind_exit is immutable; factory reset …")`. (`preview_next_state()` is a *membership* fn, `membership.rs:787`, not a role_presets one.) | blind_exit_reversal audit |
| 4.J | Enrollment token replay prevention | `rustynetd/src/enrollment_token.rs` — token consumption idempotent | enrollment_replay audit |
| 4.K | Gossip revoked-peer re-admission denial | `rustynetd/src/peer_gossip.rs` — reject bundles from revoked sources | gossip_revoked_readmit audit |
| 4.L | Revoked peer dataplane denial | `rustynetd/src/revoked_peer_denied_audit.rs` — NoopBackend eval | revoked_peer_denied audit |
| 4.M | Membership signature forgery rejection | `rustynetd/src/membership_signature_audit.rs` | signature_forgery audit |
| 4.N | Membership revoke delayed-apply | `rustynetd/src/membership_revoke_audit.rs` — 4 delayed-apply + 2 negative cases | membership_revoke audit |
| 4.O | Hello-limiter flood cap | `rustynet-relay/src/hello_limiter_audit.rs` — DOS-1 | hello_limiter_flood audit |
| 4.P | Runtime ACL integrity | `rustynetd/src/linux_runtime_acls.rs`, `macos_runtime_acls.rs`, and — note the different name — `windows_registry_acls.rs`. There is no `windows_runtime_acls.rs`. | runtime_acls stage |
| 4.Q | Service hardening | `rustynetd/src/{linux,macos,windows}_service_hardening.rs` | service_hardening stage |
| 4.R | Mesh state integrity | `rustynetd/src/{linux,macos,windows}_mesh_status.rs` | mesh_status stage |

Every control needs at least one unit test + one live-lab stage (except the planned NAS/LLM
roles, which don't have live-lab stages yet). The verifier names above are stage *families*: the
real stage IDs in `rustynet-cli/src/live_lab_stage_registry.rs` are platform-prefixed and often
have a `validate_` twin — e.g. `linux_key_custody` / `validate_linux_key_custody`,
`windows_dpapi_key_custody`, `macos_keychain_key_custody`, `linux_privileged_helper_allowlist`,
`{linux,macos,windows}_membership_signature_forgery`. Grep the registry for the exact ID before
naming a stage in a command. Use `mcp__rustynet-repo-context__get_security_controls()` (reads
`documents/SecurityMinimumBar.md` live) and `get_security_findings()` — but note the latter only
parses `SecurityReview_2026-05-24.md`'s RN-* tracker, see §15.

═══════════════════════════════════════════
9) COMMON ENGINEERING PATTERNS — HOW TO PASS REVIEW HERE
═══════════════════════════════════════════
These translate the abstract constraints (§2-§3) into concrete code shape. This is the
difference between a patch that passes review and one that gets rejected.

**9.1 Fail-closed pattern.**
```rust
// Wrong:
let state = load_trust_state().unwrap_or_default();

// Right:
let state = match load_trust_state() {
    Ok(s) => s,
    Err(e) => {
        tracing::error!(%e, "trust state unavailable; failing closed");
        return Err(AdapterError::TrustStateUnavailable);
    }
};
```
Every path that reads trust/security state handles the `None`/`Err` case explicitly and
returns an error — never defaults, never silently continues.

**9.2 No `unwrap()`/`expect()` in production paths.** They are panics, and panics are a
denial-of-service vector in security-sensitive code.
```rust
// Wrong:
let key = load_key().unwrap();
let sig = verify(&key, &data).expect("signature verification failed");

// Right:
let key = load_key().map_err(|e| AdapterError::KeyLoadFailed(e.to_string()))?;
let sig = verify(&key, &data).map_err(|e| AdapterError::SignatureInvalid(e.to_string()))?;
```
`unwrap()`/`expect()` are acceptable ONLY in: unit tests, build scripts, one-shot CLI entry
points (not library code), or a case where the invariant is locally provable AND a comment
explains why.

**9.3 Backend abstraction boundary.** Wrong: importing WireGuard types in `rustynet-control` or
`rustynet-policy`. Right: domain crates use abstract types; backend crates translate between
abstract types and concrete WireGuard types. Test with
`scripts/ci/check_backend_boundary_leakage.sh`.

**9.4 Default-deny, always.** Wrong: empty ACL → allow; empty membership → allow; missing
context → allow. Right: empty/missing/malformed → deny. The policy evaluator starts from
deny-all and only adds allows for explicitly present entries. When adding a new policy/ACL
path, the first test you write should be "empty input produces deny."

**9.5 Signed state — verify before apply.** Wrong: read a bundle, apply it, then check the
signature. Right: verify signature FIRST, check epoch/replay-watermark SECOND, apply THIRD.
Never apply unsigned or stale state.

**9.6 Secrets hygiene.** Use `tracing::Span` with fields marked for redaction. Never
`Debug`-print a type containing key material unless its `Debug` impl explicitly redacts. Test
with `scripts/ci/secrets_hygiene_gates.sh`.

**9.7 Role transitions are not just string changes** — see §7 above for the concrete rules and
`get_role_transition` (repo-context MCP) for the always-fresh version.

**9.8 Test location and naming.** Unit tests inline (`#[cfg(test)] mod tests { ... }`).
Integration tests in `crates/<name>/tests/<scenario>.rs`. Names: descriptive `snake_case`
(e.g. `gossip_three_peer_mesh`). Every security control needs one enforcement point + one
verification test.

**9.9 Commit hygiene.** Small, verifiable increments — one logical change per commit. Commit
messages: imperative mood, what AND why. Never commit generated files, build artifacts, or
secrets. Run at minimum `cargo fmt --all -- --check && cargo check -p <crate>` before
committing.

═══════════════════════════════════════════
10) GATES & DEFINITION OF DONE
═══════════════════════════════════════════
**Mandatory quality gates for substantial work** (authoritative — always confirm against
`mcp__rustynet-repo-context__get_gate_definitions()` in case this list drifts):
```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-targets --all-features
cargo audit --deny warnings
cargo deny check bans licenses sources advisories
```

The six commands above remain the authoritative gate *definition* (AGENTS.md §7), but note how
the tooling actually executes them:

**Fast-fail convenience runner** (recommended for local iteration):
`cargo run -p rustynet-xtask -- gates` runs **fmt → clippy → test** — there is NO standalone
`check` stage by default. Clippy is rustc plus lint passes, so it already provides the
compile-correctness gate at roughly the cost of `check` alone; running both would duplicate the
whole compile (no shared incremental cache across the clippy wrapper). It stops at the first
failure, streams output live, and wraps each stage in a timeout watchdog that kills the whole
process group and prints the tail on a hang.

Flags (all verified by running them):
- `--skip-test` — gate without the slow test stage.
- `-p <crate>` / any cargo scope arg — scope clippy/test; `fmt` always runs workspace-wide.
- `--with-check` — restores the old `fmt → check → clippy → test` order. This is the escape
  hatch for a broken/poisoned clippy toolchain, not the default.
- `--affected [--base <ref>]` — scope to workspace crates changed since `--base` (default
  `origin/main`, including uncommitted + untracked) plus the full transitive closure of their
  reverse-dependents. Falls back to the full workspace if a root build file
  (`Cargo.toml`/`Cargo.lock`/`rust-toolchain*`) changed or nothing is detected.
- Per-stage timeouts (seconds) via `XTASK_{FMT,CHECK,CLIPPY,TEST}_TIMEOUT` — defaults 120 /
  1200 / 1500 / 5400.

**The test stage requires `cargo-nextest`.** xtask executes tests as
`cargo nextest run … --retries 0` (retries pinned off so a flake fails loudly), and if nextest is
absent it refuses with exit code 2 *before* spending ~20min on fmt/clippy. The repo pins
**0.9.114** (`PINNED_NEXTEST_VERSION` in `crates/rustynet-xtask/src/main.rs:83`, mirrored in
`rustynet-cli/src/bin/bootstrap_ci_tools.rs` and the Windows CI leg). Install with
`cargo install cargo-nextest --locked --version 0.9.114`; CI installs it via
`scripts/ci/bootstrap_ci_tools.sh`. Each stage's wall-clock is appended to
`documents/operations/gate_timings.csv`. Exit codes: 0 pass, 1 gate failed, 124 timed out.

**Scope-specific scripts** (run the one matching your active scope document): `./scripts/ci/
phase9_gates.sh`, `phase10_gates.sh`, `membership_gates.sh`, and any other active-phase gate
script the scope document requires.

**Architecture boundary gate:** `./scripts/ci/check_backend_boundary_leakage.sh`.

**If any gate fails:** stop phase progression, fix the root cause (not the symptom), re-run the
impacted gates, and record failure/fix/proof in the relevant progress document when scope
requires it.

**Definition of Done** — work is complete only when ALL of these are true:
- in-scope requirements are implemented end-to-end
- security minimum bar controls are satisfied for that scope
- all mandatory gates pass, or the remaining blocker is explicitly documented and outside the
  claimed completion
- required artifacts exist and validate
- no unresolved in-scope blockers remain
- no TODO/FIXME/placeholders remain in completed deliverables

Cross-check against `mcp__rustynet-repo-context__get_definition_of_done()` for the always-fresh
version (from `AGENTS.md` §9).

═══════════════════════════════════════════
11) MCP SERVERS FOR REPO CONTEXT
═══════════════════════════════════════════
Two servers exist specifically to keep this doc's contents fresh instead of stale prose — use
them liberally rather than re-deriving structure by hand with `grep`/`find`.

**`rustynet-mcp-repo-context`:**
| Tool | Use |
|---|---|
| `get_read_order(task)` | Ordered doc list for a described task, per §4's precedence rules |
| `get_active_ledger(topic)` | The active ledger(s) owning a topic keyword |
| `find_in_docs(query)` | Full-text search across the entire docs tree |
| `get_document(path)` | Read one doc by repo-relative path |
| `list_documents(filter?)` | Enumerate every doc, grouped by directory, with title + line count |
| `get_definition_of_done()` | The DoD checklist from `AGENTS.md` §9 |
| `get_gate_definitions()` | The authoritative gate commands from `AGENTS.md` §7 |
| `get_architecture_constraints()` | The non-negotiable constraints from `AGENTS.md` §3 |
| `get_crate_structure()` | Per-crate summary: layer + boundary rule. **Hand-maintained static list of 17 crates — missing nas/llm-gateway/advisor/netns-probe/lab-monitor.** §6's table is more complete. |
| `get_crate_dependencies(crate)` | Internal deps + reverse deps for ONE crate. Required arg. Parsed live from `crates/*/Cargo.toml` — trustworthy. |
| `which_crate(path)` | Owning crate for a **repo-relative file path** (needs a literal `crates/<name>/` segment). NOT a symbol lookup — `which_crate("MembershipState")` returns "No owning crate". |
| `get_platform_support(feature?, platform?)` | Per-platform role/feature status. **Hand-maintained static tables** inside the MCP server, not derived from the code — see §14. |
| `get_requirements()` | `Requirements.md` content, queryable |
| `get_role_transition(from, to, platform?)` | The role-transition rules (§7 above). `from`+`to` are REQUIRED. |
| `get_security_controls(filter?)` | Section-filtered `documents/SecurityMinimumBar.md` (read live) |
| `get_security_findings(status?, severity?, id?)` | **Only** the RN-01..RN-38 tracker in `SecurityReview_2026-05-24.md`. Does NOT cover RSA-*/AUDIT-* findings — see §15. |
| `get_orchestrator_stages()` | Live-lab orchestration stage list — lab-specific; see the companion live-lab-loop doc |

**`rustynet-mcp-gate-runner`:**
| Tool | Use |
|---|---|
| `run_gates(scope?, skip_test?, changed_only?)` | fmt→check→clippy→test via xtask; `changed_only:true` auto-scopes to what you touched |
| `run_fmt()` / `run_check(scope?)` / `run_clippy(scope?)` / `run_test(scope?, nocapture?)` / `run_build(scope?, release?)` | Individual gate commands |
| `run_security_audit()` | `cargo audit` + `cargo deny check bans licenses sources advisories` |
| `run_security_gates(skip_audit?)` | The full local security-critical bundle — secrets-hygiene, backend-boundary-leakage, no-leak-dataplane, security-regression, supply-chain-integrity, role-auth-matrix, dependency-exceptions, anchor-secret-redaction, traversal-adversarial, active-network-security, plus audit/deny. Run after touching trust/dataplane/crypto/policy/membership code. |
| `list_gate_scripts()` | The `scripts/ci/*.sh` catalog, grouped by category, flagged when lab-dependent |
| `run_gate_script(script)` / `run_gate_scripts(scripts[])` | Run one or a curated set of `scripts/ci/*.sh` gate scripts with an aggregated verdict |

═══════════════════════════════════════════
12) DOCUMENTATION HYGIENE RULES
═══════════════════════════════════════════
- `documents/README.md` is the top-level map; `documents/operations/README.md` is the
  operations/runbook map; `documents/operations/active/README.md` is the active-work map.
- If you add, remove, rename, archive, or materially repurpose a doc, update the relevant index
  in the **same change**.
- If a document becomes historical rather than active, move or reclassify it honestly (into
  `operations/done/` or `documents/archive/`) in the same change.
- Do not reintroduce standalone prompt or status documents; keep execution guidance in the
  active ledgers themselves.
- **Exception — three operator-sanctioned, repo-root prompt templates:** this doc
  (`rustynet_repo_context_prompt.md`), its companion `rustynet_live_lab_loop_prompt.md`, and
  `rustynet_hard_problem_prompt.md` (the hard-problem brief prepended to reasoning calls, added
  2026-07-18 in `2881aea2`). None is source-of-truth guidance (the active ledgers are) and none
  should be deleted as a "stale prompt doc" — keep all three current with the architecture,
  tooling, and MCP functions they reference.
- `AGENTS.md` and `CLAUDE.md` are intentionally byte-for-byte mirrored. Any edit to one MUST be
  applied identically to the other in the same change. When a crate, ledger, or top-level
  directory is added/moved/renamed, update §2/§11/§12 there (and the mirror) plus
  `documents/CODE_MAP.md` so the structure map does not drift from the code.
- Remove dead links, stale index entries, and prompt-only guidance when you find them.

═══════════════════════════════════════════
13) FULL CLI COMMAND SURFACE — the DEFAULT-FEATURE (shipped) `rustynet` binary
═══════════════════════════════════════════
This block is the complete subcommand surface of the shipped binary, re-verified 2026-07-27 as
**byte-identical** to `rustynet-cli --help` built with default features (no `vm-lab`).
Structural, low-churn — read once, don't re-derive with `--help` every session. Still run
`rustynet <verb> --help` for the exact flags of a command you are about to run.

Under `--features vm-lab` the surface roughly doubles (241 help lines vs 124): the whole
`ops vm-lab-*` fleet-control family, plus every `ops e2e-*`, `ops write-live-*`,
`ops *-cross-network-*`, `ops validate-live-lab-*`, `ops run-*-gates`, `ops install-windows-*`
and assorted lab helpers. **All of those are vm-lab-gated, not just the `vm-lab-` prefixed
ones** — if a verb you expect is absent below, check whether it needs `--features vm-lab`
before concluding it does not exist. They are documented in the companion
`rustynet_live_lab_loop_prompt.md`.

```
status [--json]
login
netcheck [--json]
version
info
doctor
logs [--follow] [--level <level>] [--lines <n>]
config show
debug
peer-list
tunnel-info
exit-node-list
role [show|set <admin|client|blind_exit>]
role pin-port-mapping-authority [--node <id> | --clear [--node <id>]] --output <path> [--reason <code>] [--policy-context <ctx>] [--expires-in <secs>] [--update-id <id>] [--snapshot <path>] [--log <path>]
role recommend [--role anchor|relay|exit] [--snapshot <path>] [--log <path>]
llm allow <node:id|group:name> [--models a,b] [--quota <tokens>] [--rate <req/min>]
llm deny <node:id|group:name>
llm access list
connectivity-test
peer-stats
bandwidth
metrics
dns-test [<domain>]
state refresh
install [--role node|relay|exit|anchor] [--dry-run] [--unattended] [--from-dir <abs> | --build-from-source] [--owner-key-file <abs>] [--owner-key-thumbprint <hex>] [--uninstall]
operator menu
exit-node select <node>
exit-node off
lan-access on|off
dns inspect
dns zone issue --signing-secret <path> --signing-secret-passphrase-file <path> --subject-node-id <id> --nodes <node_specs> --allow <allow_specs> --records-manifest <path> --output <path> [--zone-name <name>] [--ttl-secs <secs>] [--generated-at <unix>] [--nonce <n>] [--verifier-key-output <path>]
dns zone verify --bundle <path> --verifier-key <path> [--expected-zone-name <name>] [--expected-subject-node-id <id>]
traversal issue --signing-secret <path> --signing-secret-passphrase-file <path> --source-node-id <id> --target-node-id <id> --nodes <node_specs> --allow <allow_specs> --candidates <type|endpoint|priority[|relay_id];...> --output <path> [--ttl-secs <secs>] [--generated-at <unix>] [--nonce <n>] [--verifier-key-output <path>]
traversal verify --bundle <path> --verifier-key <path> --watermark <path> [--expected-source-node-id <id>] [--max-age-secs <secs>] [--max-clock-skew-secs <secs>]
route advertise <cidr>
key rotate
key revoke
assignment issue --target-node-id <id> --nodes <node_specs> --allow <allow_specs> --signing-secret <path> --signing-secret-passphrase-file <path> --output <path> [--verifier-key-output <path>] [--mesh-cidr <cidr>] [--exit-node-id <id>] [--lan-routes <csv>] [--ttl-secs <secs>] [--generated-at <unix>] [--nonce <n>]
assignment verify --bundle <path> --verifier-key <path> --watermark <path> [--expected-node-id <id>] [--max-age-secs <secs>] [--max-clock-skew-secs <secs>]
assignment init-signing-secret --output <path> --signing-secret-passphrase-file <path> [--length-bytes <n>] [--force]
  node_specs format: node_id|endpoint|public_key_hex[|owner|hostname|os|tags_csv|capabilities_csv];...
  allow_specs format: source_node_id|destination_node_id;...
membership status [--snapshot <path>] [--log <path>]
membership list [--snapshot <path>] [--log <path>]
membership propose --operation <add-node|remove-node|revoke-node|restore-node|rotate-node-key|set-node-capabilities|set-quorum|rotate-approver> --output <path> [operation flags] [--reason <code>] [--policy-context <ctx>] [--expires-in <secs>] [--update-id <id>] [--snapshot <path>] [--log <path>]
membership propose-add --node-id <id> --node-pubkey <hex> --owner <owner> --output <path> [--roles <csv>] [--capabilities <csv>] [--reason <code>] [--policy-context <ctx>] [--expires-in <secs>] [--update-id <id>] [--snapshot <path>] [--log <path>]
membership propose-remove --node-id <id> --output <path> [--reason <code>] [--expires-in <secs>] [--snapshot <path>] [--log <path>]
membership propose-revoke --node-id <id> --output <path> [--reason <code>] [--expires-in <secs>] [--snapshot <path>] [--log <path>]
membership propose-restore --node-id <id> --output <path> [--reason <code>] [--expires-in <secs>] [--snapshot <path>] [--log <path>]
membership propose-rotate-key --node-id <id> --new-pubkey <hex> --output <path> [--reason <code>] [--expires-in <secs>] [--snapshot <path>] [--log <path>]
membership propose-set-capabilities --node-id <id> --capabilities <csv> --output <path> [--reason <code>] [--expires-in <secs>] [--snapshot <path>] [--log <path>]
membership propose-set-quorum --threshold <n> --output <path> [--reason <code>] [--expires-in <secs>] [--snapshot <path>] [--log <path>]
membership propose-rotate-approver --approver-id <id> --approver-pubkey <hex> --role <owner|guardian> --status <active|revoked> --output <path> [--reason <code>] [--expires-in <secs>] [--snapshot <path>] [--log <path>]
membership sign-update --record <path> --approver-id <id> --signing-key <path> --signing-key-passphrase-file <path> --output <path> [--merge-from <signed-update-path>]
membership sign --record <path> --approver-id <id> --signing-key <path> --signing-key-passphrase-file <path> --output <path> [--merge-from <signed-update-path>]
membership verify-update --signed-update <path> [--snapshot <path>] [--log <path>] [--now <unix>] [--dry-run]
membership apply-update --signed-update <path> [--snapshot <path>] [--log <path>] [--now <unix>] [--dry-run] [--daemon]
membership apply --signed-update <path> [--snapshot <path>] [--log <path>] [--now <unix>] [--dry-run] [--daemon]
membership verify-log [--snapshot <path>] [--log <path>] [--audit-output <path>] [--now <unix>]
membership verify [--snapshot <path>] [--log <path>] [--audit-output <path>] [--now <unix>]
membership generate-evidence [--snapshot <path>] [--log <path>] [--output-dir <dir>] [--environment <label>] [--now <unix>]
trust keygen --signing-key-output <path> --signing-key-passphrase-file <path> --verifier-key-output <path> [--force]
trust export-verifier-key --signing-key <path> --signing-key-passphrase-file <path> --output <path>
trust issue --signing-key <path> --signing-key-passphrase-file <path> --output <path> [--updated-at-unix <unix>] [--nonce <n>]
trust verify --evidence <path> --verifier-key <path> --watermark <path> [--max-age-secs <secs>] [--max-clock-skew-secs <secs>]
ops refresh-trust
ops verify-runtime-binary-custody
ops refresh-signed-trust
ops bootstrap-wireguard-custody
ops refresh-assignment
ops state-refresh-if-socket-present
ops collect-phase1-measured-input
ops run-phase1-baseline
ops generate-attack-matrix --attacks <csv> --nodes <csv> --output <path> [--format <md|json>]
ops generate-assessment-from-matrix --project <name> --matrix-json <path> --output <path> [--topology <text>] [--authorization <text>]
ops check-no-unsafe-rust-sources [--root <path>]
ops check-dependency-exceptions [--path <path>]
ops check-perf-regression [--phase1-report <path>] [--phase3-report <path>]
ops check-secrets-hygiene [--root <path>]
ops collect-phase9-raw-evidence
ops generate-phase9-artifacts
ops verify-phase9-readiness
ops verify-phase9-evidence
ops generate-phase10-artifacts
ops verify-phase10-readiness
ops verify-phase10-provenance
ops write-phase10-hp2-traversal-reports --source-dir <path> --environment <label> --path-selection-log <path> --probe-security-log <path>
ops verify-phase6-platform-readiness
ops verify-phase6-parity-evidence
ops verify-required-test-output --output <path> --package <name> --test-filter <pattern>
ops validate-network-discovery-bundle [--bundle <path>]... [--bundles <path[,path...]>] [--max-age-seconds <secs>] [--require-verifier-keys] [--require-daemon-active] [--require-socket-present] [--output <path>]
ops write-unsigned-release-provenance --input <path> --output <path>
ops sign-release-artifact
ops verify-release-artifact
ops collect-platform-probe
ops generate-platform-parity-report
ops collect-platform-parity-bundle
ops install-systemd
ops prepare-system-dirs
ops restart-runtime-service
ops stop-runtime-service
ops show-runtime-service-status
ops start-assignment-refresh-service
ops check-assignment-refresh-availability
ops install-trust-material --verifier-source <absolute-path> --trust-source <absolute-path> --verifier-dest <absolute-path> --trust-dest <absolute-path> [--daemon-group <group>]
ops create-release-manifest --artifact <name>:<target>:<path> [--artifact ...] --signing-seed-file <path> --output <path> [--release-track <track>] [--key-id <id>] [--generated-at-unix <secs>]
ops verify-release-manifest --manifest <path> (--pinned-verifier-key-hex <hex> | --pinned-verifier-key-file <path>) [--artifacts-dir <dir>]
ops apply-managed-dns-routing
ops clear-managed-dns-routing
ops disconnect-cleanup
ops apply-blind-exit-lockdown
ops init-membership
ops secure-remove --path <absolute-path>
ops ensure-signing-passphrase-material
ops ensure-local-trust-material --signing-key-passphrase-file <absolute-path>
ops materialize-signing-passphrase --output <absolute-path>
ops materialize-signing-passphrase-temp
ops set-assignment-refresh-exit-node [--env-path <absolute-path>] [--exit-node-id <id>]
ops force-local-assignment-refresh-now
ops apply-lan-access-coupling --enable <true|false> [--lan-routes <cidr[,cidr...]>] [--env-path <absolute-path>]
ops apply-role-coupling --target-role <admin|client> [--preferred-exit-node-id <id>] [--enable-exit-advertise <true|false>] [--env-path <absolute-path>] [--skip-client-exit-route-convergence-wait]
ops peer-store-validate --config-dir <absolute-path> --peers-file <absolute-path>
ops peer-store-list --config-dir <absolute-path> --peers-file <absolute-path> [--role <role>] [--node-id <id>]
```
═══════════════════════════════════════════
14) PLATFORM SUPPORT MATRIX (hand-maintained — read the provenance note before trusting it)
═══════════════════════════════════════════
**Provenance, verified 2026-07-27 — this matters, an earlier version of this section claimed a
code-derived source it does not have:**
- These tables are a copy of the **hand-maintained static tables inside the repo-context MCP
  server** — `role_support()` (`crates/rustynet-mcp/src/bin/repo_context.rs:1685`) and
  `static PLATFORM_FEATURES` (`:1818`). Calling
  `mcp__rustynet-repo-context__get_platform_support()` returns the same hand-written data, so it
  is **not** an independent re-verification. Nothing here is generated from the code.
- `is_blind_exit_supported_host` IS a live production gate
  (`rustynet-operator/src/role.rs:81`, called from `normalize_role` at `:111`) and agrees with
  the `blind_exit` row.
- `NodeRole::is_supported_for_platform` (`rustynet-cli/src/vm_lab/orchestrator/role.rs:60`) is
  **NOT** a live gate: it has no production caller — every non-test reference is a comment, and
  the module carries `#![allow(dead_code)]`. The gate the orchestrator actually consults is
  `is_lab_assignable_for_platform` (`vm_lab/orchestrator/native.rs:266,440`).
- That dead function also **disagrees** with the table below: it restricts `Admin` (and
  `Anchor`/`Relay`) to Linux, while `admin` is recorded ✅ on macOS and Windows here. The ✅ is
  the better-evidenced side — `CrossPlatformRoleParityPlan_2026-06-21.md:57` records
  `validate_macos_admin_issue` PASS (run `livelab-1782135034`, 2026-06-22) and
  `validate_windows_admin_issue` PASS (run `livelab-1782526081`, 2026-06-27). The stale artifact
  is the code gate, not the matrix. **Do not "fix" the matrix to match that function.**

For a real release decision, go to `CrossPlatformRoleParityPlan_2026-06-21.md` (the
release-blocking per-role × OS live-proof matrix) — not to this snapshot and not to the MCP.

**Roles × OS** (✅ supported/live-evidence · ⛔ fail-closed — implemented + lab-assignable, pending
live evidence · 📋 planned · 🚫 blocked by design):
| Role | linux | macos | windows | ios | android |
|---|---|---|---|---|---|
| client | ✅ | ✅ | ✅ | 📋 (mobile client-only, adapter not shipped) | 📋 (same) |
| admin | ✅ | ✅ | ✅ | 🚫 | 🚫 |
| exit | ✅ | ✅ | ⛔ (gated until W5.4 WinNAT/HNS live evidence) | 🚫 | 🚫 |
| blind_exit | ✅ | ✅ | 🚫 (not a supported blind_exit host) | 🚫 | 🚫 |
| relay | ✅ | ⛔ (lab-assignable; pending Phase-8 cross-OS green run) | ⛔ (same) | 🚫 | 🚫 |
| anchor | ✅ | ⛔ (same) | ⛔ (same) | 🚫 | 🚫 |
| nas | ⛔ (D13.c/D13.d in progress; pending Linux live-lab evidence row) | ⛔ (secondary host; pending cross-OS green run) | ⛔ (gated on D7/D9 Windows dataplane parity) | 🚫 | 🚫 |
| llm | ⛔ (same as nas) | ⛔ (same) | ⛔ (same) | 🚫 | 🚫 |

**Features × OS:**
| Feature | Status |
|---|---|
| killswitch (linux) | ✅ supported — nftables pre-start and post-start |
| killswitch (macos) | ⛔ fail-closed — pf anchor available; pre-killswitch not yet mandatory |
| killswitch (windows) | ⛔ fail-closed — netsh-based; IPv4 LAN egress allow-all is RN-06 (open); WFP migration planned |
| wireguard-kernel (linux) | ✅ in-kernel WireGuard via the `linux-wireguard` backend mode (`rustynetd/src/daemon.rs:863`) |
| wireguard-userspace (macos) | ✅ boringtun userspace backend (`MacosUserspaceSharedBackend`, in `rustynet-backend-wireguard`) |
| wireguard-nt (windows) | ⛔ **opt-in, NOT release-gated support.** The `windows-wireguard-nt` label exists (`rustynetd/src/windows_backend_gate.rs:4`) but the default label is `windows-unsupported`, which fail-closes (`require_supported_windows_backend`, `:22-29`), and the code states the mode "is opt-in and still outside release-gated support until measured evidence exists" (`windows_service.rs:421`). It is also **not** a directly-loaded WireGuardNT DLL: the adapter shells out to the official WireGuard-for-Windows `wireguard.exe`/`wg.exe` and readiness fails closed if they are absent (`windows_backend_readiness.rs:6-34`). |
| dpapi-secrets (windows) | ✅ DPAPI-protected blobs under `C:\ProgramData\RustyNet\secrets` (`rustynetd/src/windows_paths.rs:12`, `windows_key_custody.rs:291`) |
| keychain-secrets (macos) | ✅ macOS keychain key custody (`SecKeychain`, `rustynet-crypto/src/lib.rs:21,311,331`) |
| ipv6-dataplane (linux) | ✅ dual-stack with v6 candidate gathering (`rustynetd/src/dataplane_candidates.rs`, `linux_ipv6_leak.rs`) |
| upnp-natpmp-pcp (linux) | ✅ gateway detection via `/proc/net/route` (`rustynet-sysinfo/src/lib.rs`, `rustynetd/src/port_mapper.rs`) |

**The single biggest structural gap driving the Linux-VM-host program (companion doc §5.6):**
Windows exit/blind_exit is fail-closed/blocked specifically because Apple-Silicon UTM/QEMU exposes
no nested virtualization, so a Windows guest on the Mac lab can never run WinNAT — this is why
`ubuntu-kvm-1` (real x86 KVM nested virt) exists.

═══════════════════════════════════════════
15) CURRENT STANDING SECURITY POSTURE (dated snapshot — cross-check before treating as current)
═══════════════════════════════════════════
Three overlapping audit generations exist; newest supersedes older on any conflict, but none formally
retires the last — cross-check the ledger, not just the newest date, when the stakes are high.

**Newest, broadest: `documents/operations/active/SecurityAuditLedger_2026-06-18.md`** — file-by-file
audit against `SecurityMinimumBar.md`, coverage-complete (594/594 tracked files). **76 findings raised
→ 2 withdrawn as false-positive → 74 standing: 0 Critical / 2 High / 15 Medium / 34 Low / 19 Info / 4
Question.** Those counts are the ledger's own as-written state (2026-06-18/19) and still match it.

**The two Highs it lists are BOTH FIXED — do not start work believing revocation is broken.**
`SecurityRemediationPlan_2026-06-19.md:11` records both as **APPLIED 2026-06-24**, and the code
confirms it (verified 2026-07-27):
- **RSA-0009** (membership reducer stamped `unix_now()` into the canonical state-root, so
  Revoke/RotateKey/Restore/SetCapabilities could never apply) — **FIXED.**
  `apply_signed_update` now re-derives with the *signed record's own* `created_at_unix`
  (`rustynet-control/src/membership.rs:940-947`; see the `RSA-0009` note at `:1847`), with a
  dedicated regression audit (`rustynetd/src/membership_revoke_audit.rs`, "Adversarial self-audit
  proving RSA-0009's fix actually works") wired to fail loudly if it regresses
  (`rustynetd/src/main.rs:1975`), plus Tier-0 live-lab stages added 2026-07-01 (`b101a1f0`).
- **RSA-0063** (macOS bootstrap could leave `NOPASSWD: ALL` in sudoers → local privesc) —
  **FIXED.** EXIT-trap removal on every exit path,
  `scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh:310`, mirrored in
  `rustynet-cli/src/vm_lab/orchestrator/adapter/macos_install.rs:1951`.

The rest of the ledger's 74 findings remain review-only proposals awaiting human approval — the
audit itself changed no production code/crypto/config. So: the ledger is a valid *inventory* but
its High row is stale; the remediation plan is the status of record.

**Prior full-repo pass: `documents/operations/active/SecurityAndQualityAudit_2026-06-10.md`** — 14
independent deep reviews, first-hand verified. **53 net-new findings (AUDIT-001..053): 0 Critical /
11 High / 19 Medium / 16 Low / 7 Info.** Verdict at the time: **NO-SHIP until the P0 set closes.** Top
risks flagged: the fail-closed killswitch could fail open (RN-03/04/10 — since fixed per the ledger
above), the (now-superseded, do-not-run-without-`--dry-run`) uncommitted overnight driver's live path
was destructive, `lab_state` MCP `report_dir` was unconfined (AUDIT-006 — since remediated), the
membership reducer non-determinism (AUDIT-040 = RSA-0009 — **since fixed**, see above), Windows
encrypted-key custody ACL was a no-op (AUDIT-027/RN-33), a relay pre-auth DoS (AUDIT-031), and the
macOS bootstrap `NOPASSWD: ALL` sudoers residue (AUDIT-045/RN-32 = RSA-0063 — **since fixed**).

**Sequencing and status of record:** `documents/operations/active/SecurityRemediationPlan_2026-06-19.md`
sequences the audit ledger's findings into waves (P0 = the 2 Highs, both now APPLIED; P1 = Mediums by
7 systemic themes; P2 = Low/Info by category) with per-item fix + verification test + effort estimate.
Read this file for CURRENT status, not the ledger's severity table.

**Original firm-grade review (older, narrower, still referenced): `documents/operations/active/
SecurityReview_2026-05-24.md`** (RN-* namespace, 38 findings across 6 domains) — most Highs/Mediums
here have since been fixed (tracked via `RL-#` remediation-log entries); `RN-02/06/07` remained open
as of the newer audits' cross-reference. Use `mcp__rustynet-repo-context__get_security_findings()` for
the machine-parsed live version of this specific file — it does NOT cover the newer RSA-*/AUDIT-*
findings above, so don't treat its "all fixed" rows as the whole security picture.

**Practical rule:** before touching crypto/auth/policy/trust-state code, grep the relevant crate's
findings across all three ledgers by RN-*/AUDIT-*/RSA-* number, and check the *remediation plan* (not
the ledger) for status. Every "still open" framing in a dated audit doc is a claim about the day it
was written — confirm against code before building on it. There is a repo pattern here: this doc's
own RSA-0009/RSA-0063 rows were stale by a month, and `DocCodeDiscrepancyAudit_2026-07-18.md` exists
because doc-vs-code drift is a recurring failure mode in this repo.

There are also newer security docs than the three below — e.g.
`AnchorBundlePullAttestationSecurityReview_2026-07-20.md`,
`SecurityAuditAndMainConsolidation_2026-07-21.md`, `LinuxMtuPrivilegedHelperAllowlistGap_2026-07-21.md`,
`QH01TemplateInjectionFixPlan_2026-07-25.md`. Run
`list_documents(filter: "operations/active")` rather than assuming §15 or §17 enumerates everything.

═══════════════════════════════════════════
16) FULL CI GATE SCRIPT CATALOG (`scripts/ci/*.sh`, 51 scripts — verified 2026-07-27)
═══════════════════════════════════════════
From `mcp__rustynet-gate-runner__list_gate_scripts()`. Run the curated security set with
`run_security_gates`; run any hand-picked set with `run_gate_scripts([...])`; lab-dependent ones need
a live VM lab (drive them via the live-lab-loop doc's tooling, not directly).

**security (10):** `active_network_security_gates.sh`, `anchor_secret_redaction_gates.sh`,
`check_backend_boundary_leakage.sh`, `check_dependency_exceptions.sh`, `no_leak_dataplane_gate.sh`,
`role_auth_matrix_gates.sh`, `secrets_hygiene_gates.sh`, `security_regression_gates.sh` (Rust-based;
supersedes the historical grep-based secret scan), `supply_chain_integrity_gates.sh`,
`traversal_adversarial_gates.sh`.

**role / platform (8):** `anchor_downgrade_gates.sh`, `anchor_role_gates.sh`,
`llm_exit_coexistence_gates.sh` (D13.d LLM↔exit coexistence), `phase10_cross_network_exit_gates.sh`,
`role_taxonomy_gates.sh` (eight-preset taxonomy, D12+D13), `role_transition_audit_gates.sh`,
`service_hosting_role_gates.sh` (D13.e), `test_validate_cross_network_remote_exit_reports.sh`.

**phase (13):** `check_phase10_readiness.sh`, `check_phase6_platform_parity.sh`,
`check_phase9_readiness.sh`, `phase10_gates.sh`, `phase10_hp2_gates.sh`, `phase1_gates.sh`,
`phase3_gates.sh`, `phase4_gates.sh`, `phase5_gates.sh`, `phase6_gates.sh`, `phase7_gates.sh`,
`phase8_gates.sh`, `phase9_gates.sh`.

**release / readiness (6):** `check_fresh_install_os_matrix_readiness.sh`,
`fresh_install_os_matrix_release_gate.sh`, `perf_regression_gate.sh`,
`regression_coverage_gates.sh` (X7, per-platform regression-coverage floor), `release_readiness_gates.sh`,
`test_check_fresh_install_os_matrix_readiness.sh`.

**lab-dependent, needs VMs (6):** `anchor_live_lab_gates.sh`, `chaos_gates.sh`,
`cross_platform_role_gates.sh` (Track B: B1.4/B1.5/M1/M2/W1/W4), `linux_exit_role_gates.sh`
(hermetic — validates without necessarily running live), `orchestrator_engine_gates.sh` (Rust-native
orchestrator engine gates), `windows_cross_compile_gate.sh`.

**other (8):** `bootstrap_ci_tools.sh` (dispatches to the Rust `bootstrap_ci_tools` binary — this is
what installs the pinned `cargo-nextest`), `check_mcp_binaries_fresh.sh` (added 2026-07-17 in
`adae8a94` — fails loud when a prebuilt MCP server binary under `bin/` is stale),
`lab_monitor_gates.sh` (standalone gate for the excluded `rustynet-lab-monitor` crate),
`llm_default_deny_gates.sh` (D13.d §9), `membership_gates.sh`, `nas_default_deny_gates.sh` (D13.c
§7), `run_required_test.sh`, `windows_compile_check.sh` (local Windows compile gate, readiness plan
E1).

═══════════════════════════════════════════
17) FULL ACTIVE-LEDGER INDEX — SNAPSHOT (dated; the file itself is the live source)
═══════════════════════════════════════════
This is a captured copy of `documents/operations/active/README.md`'s annotated ledger list — the
single richest "what's currently being worked and why" index in the repo — embedded here so a fresh
agent doesn't have to spend a tool call reading it before getting oriented. **It WILL drift**: ledgers
move to `done/`, new ones appear, statuses change. **Snapshot date: 2026-07-17.** Every filename
below still exists (all 76 checked 2026-07-27), but `operations/active/` has since grown by ~19
documents that are NOT listed here (2026-07-18 onward: `DocCodeDiscrepancyAudit_2026-07-18`,
`EfficiencyAndAdvancedTechniqueOpportunityCatalog_2026-07-19`, `RepoReview_2026-07-20`,
`AnchorBundlePull*_2026-07-20`, `SecurityAuditAndMainConsolidation_2026-07-21`,
`BlindExitPcbHardwarePlan_2026-07-22`, `NodeEngineAcceptanceSpec_2026-07-23`,
`CrossPlatformRoleParityRefresh_2026-07-23`, `BashRetirementPlan_2026-07-24`,
`QualityHardeningTodo_2026-07-25`, and others). Treat every annotation below as "true as of
2026-07-17" and re-read `documents/operations/active/README.md` directly (one file read, not a
tool round-trip) before making any claim that depends on current status. Paths below are repo-relative
under `documents/operations/active/` unless otherwise noted.

**Primary execution ledgers (start here for current status):**
- `RustynetUnifiedTodoLedger_2026-07-10.md` — dated repository-wide TODO roll-up covering
  security/release blockers, the full live-lab verification ladder, completion of the Rust `--node`
  engine, canonical dual-plane VM networking and MCP behavior, desktop role parity, cross-network
  dataplane, Android/iOS client programs, NAS/LLM evidence, testing/fuzzing, serialization,
  CI/supply chain, performance, operations, platform expansion, external decisions, and one shared
  Definition of Done. Focused ledgers remain authoritative; both get updated as work lands.
- `ParallelAgentWorkPlan_2026-07-01.md` — partitions the backlog into independent big jobs for
  concurrent agents (HP-3 real relay packet-forwarding proof; cross-OS role transitions + Windows
  anchor live bundle-serving; a Tier-1 security-hardening batch); documents the git-worktree-per-job
  mechanics. Ready-to-paste prompts in `ParallelAgentPrompts_2026-07-01/`.
- `NonSecurityParallelHandoff_2026-07-13.md` — stand-alone multi-model dispatch prompt for the
  guardrail-safe NON-security backlog (durability, refactor, tests, tooling, diagnostics, docs),
  explicitly excluding the crypto/trust-state/killswitch/exit-NAT/DNS-failclosed/privileged-helper/ACL
  surfaces (those stay on the Opus + §13.2 path). Tiers work by model.
- `LabMonitorTUIDesign_2026-06-29.md` — design spec for `rustynet-lab-monitor`: the pixelated
  terminal TUI live GUI for the parity campaign. New crate `crates/rustynet-lab-monitor/`; ratatui
  0.28 + crossterm + tokio; reads state files directly, no MCP dependency at runtime.
- `LiveLabMonitorTUIAccuracyImprovements_2026-07-10.md` — implemented monitor truth/freshness
  hardening: active TSV precedence, invocation-correct resume manifests, fail-loud manifest/data
  errors, schema-v2 fetched test counts, source-age display, complete UTM discovery, explicit VM
  power/online/readiness/run-use columns, canonical cross-platform toolchain preflight, run-backed
  roles only.
- `DeepSeekLiveLabOrchestrationPipeline_2026-06-27.md` — the DESIGN doc behind the whole DeepSeek
  live-lab MCP layer (companion doc §3/§5.6 covers the built/live version of this).
- `LiveLabSecurityTestCoverage_2026-06-22.md` — threat-coverage map for the adversarial live-lab
  security suite: 18 vulnerability classes × `SecurityMinimumBar` controls × existing coverage, the
  two CRITICAL trust-path bugs (now code-fixed, verified 2026-07-01) but still needing live-lab
  proof at the time of writing, the corrected relay-forwarding status, and the 111-item full backlog
  by surface. Its priority section is noted stale as of 2026-07-04 — see the status-check doc.
- `SecurityStageBacklogStatusCheck_2026-07-04.md` — read-only status check confirming 6
  previously-called-unbuilt items are in fact done, confirming 2 lab-monitor GUI backlog items are
  still open, and flagging 2 gaps in the stage-contract program.
- `CrossPlatformRoleParityPlan_2026-06-21.md` — **RELEASE-BLOCKING COMPLETENESS MANDATE**: every
  node role + capability must work and be LIVE-LAB-PROVEN on macOS AND Windows, not just Linux. The
  single source of truth for the live-proven status matrix per role × OS (companion §14 mirrors the
  code-level version of this).
- `LiveLabStageContractPlan_2026-07-03.md` — the live-lab stage-contract program: one data registry
  owns the stage vocabulary, every run emits a run-scoped stage manifest, the run matrix upserts by
  run key, a closed terminal-state taxonomy prevents planned stages from evaporating silently.
- `LiveLabFindings_2026-07-03.md` — the 2026-07-03 end-to-end live-lab findings pass; implemented by
  the StageContractPlan above.
- `LiveLabStageTriageLedgerPlan_2026-07-16.md` — the stage triage ledger design (companion doc R12
  covers the built mechanism).
- `LiveLabFindings_2026-07-12.md` — findings from driving `live_managed_dns_validation` to green;
  records three problems it unmasked (reboot-recovery missing assignment-refresh.env in focused
  setup; Linux exit daemon-role stale-env; a latent client-less exit spec).
- `TrackC_BashOrchestratorDefects_2026-07-13.md` — legacy bash-orchestrator defects found pairing it
  against the Rust `--node` engine. Per owner decision the retiring bash path is DOCUMENTED, not
  fixed.
- `RustNativeNodeOrchestratorQualityAudit_2026-07-10.md` — the 2026-07-10 quality audit +
  implementation ledger for the Rust `--node` engine: 17 source-verified findings, most now
  core-code-fixed with remaining live/fault-injection proof where applicable.
- `RustNodeOrchestratorCompletionBrief_2026-07-12.md` — completion brief for the Rust `--node`
  orchestrator: Definition of Done across Track A (structural) / B (parity gate) / C (evidence) / D
  (promotion/retirement).
- `MacWinStageParityPlan_2026-07-02.md` — cross-platform stage parity plan: macOS/Windows have 14
  fewer one-off validators than Linux; the Tier 0-4 roadmap to close it.
- `TrackC_Pair1_Linux_2026-07-13.md` — first paired bash↔Rust functional-parity run (2-node Linux
  exit+client): G1-G8 scorecard, NOT yet full PASS at the time, one finding since resolved.
- `LiveLabExecutionEfficiencyPlan_2026-06-20.md` — the operating method for the "drive defects to
  zero" live-lab loop (companion doc §1 and §5 embed this method directly).
- `CrossPlatformRoleParityRoadmap_2026-06-22.md` — the execution roadmap operationalizing the parity
  mandate: remaining work + effort per mac/win role cell, ordered implementation program, the
  FAIL-LOUD live-stage spec, the optimized concurrent Windows+macOS test pipeline.
- `AutonomousSecurityParityPassLog_2026-06-24.md` — progress log for a 2026-06-24 code-only
  security+parity pass, including a HIGH killswitch-bypass found and fixed.
- `LiveLabCoverageAndHonestyAudit_2026-06-25.md` — cross-OS live-lab coverage + capture-honesty gap
  map: the role × OS coverage matrix, the security-surface × OS matrix (every adversarial surface at
  the time was Linux-only), ranked capture-honesty findings, a Wave 0-5 remediation plan.
- `FocusedLiveLabRoleGapAnalysis_2026-07-02.md` — focused static analysis of Linux `blind_exit`,
  macOS `admin`, Windows `anchor.bundle_pull` (no live labs run for this doc).
- `LiveLabWave0_LinuxHonestyFixes_2026-06-25.md` through `LiveLabWave5Chaos_InertScaffolds_2026-06-25.md`
  — the Wave 0/1/2/5 implementation specs from the coverage audit (honesty fixes, integrated-pipeline
  honest skips, core-role cross-OS parity port, the 3 real chaos scaffolds).
- `LinuxBlindExitDataplane_2026-06-25.md` — closed the fail-OPEN `blind_exit`-on-Linux gap (new
  `linux_blind_exit` nftables module).
- `CrossPlatformCiHealth_2026-06-25.md` — cross-platform-CI breakage cleanup + the windows-gnu
  cross-clippy runbook; cleared ~80+ pre-existing Windows clippy errors; fixed a real Windows
  trust-state persist bug.
- `CrossOsRoleSwitchPlan_2026-06-24.md` — design for the live cross-OS role-transition parity cell.
- `RustynetDataplaneExecutionPlan_2026-05-18.md` — source-of-truth for the cross-network dataplane
  track (D2-D13): peer-distributed coordination, home-server-as-zero-ingress-relay, uPnP/IPv6/ICE,
  enrollment-token onboarding, anchor-role formalisation, 8-role user-selectable surface.
- `CrossNetworkSubstrateIntegrationSpec_2026-06-21.md` — makes the cross-network live-lab stages
  actually run: substrate↔validator mapping (netns Tier A, vxlan Tier B, slirp Tier C), orchestrator
  wiring, phased plan.
- `LiveLabVmConnectivityImplementation_2026-07-10.md` — execution ledger for the VM connectivity
  rulebook (dual-plane lab-network program, slices A-E).
- `DataplanePerfBacklog_2026-06-12.md` — remaining hot-path performance items with expected impact,
  approach, invariant pins, and criterion bench targets.
- `NodeRoleTaxonomy_2026-05-21.md` — canonical taxonomy for the six user-selectable node roles.
- `AnchorNodeRoleDesign_2026-05-21.md` — canonical design for the anchor role.
- `NodeRoleTaxonomyExtension_2026-06-11.md` — extends the taxonomy to eight roles by adding `nas`/`llm`.
- `NasNodeRoleDesign_2026-06-11.md` / `LlmNodeRoleDesign_2026-06-11.md` — deep dives for the two
  service-hosting roles.
- `ServiceHostingRolesDeltaPlan_2026-06-11.md` / `ServiceHostingRolesRoadmap_2026-06-11.md` — the D13
  delta ledger + program roadmap (milestones M0-M6).
- `MasterWorkPlan_2026-03-22.md`, `PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md`,
  `OpenWorkIndex_2026-04-17.md` — long-standing cross-cutting work plans.

**Active phase checklists (still open — Phase 1/2/3/5 finished, archived in `done/`):**
`Phase4LiveLabEvidenceRefreshChecklist_2026-04-12.md` (fresh-install + canonical cross-network
evidence regeneration for a clean HEAD), `Phase5ReleaseReadinessSummary_2026-04-12.md` (operator-facing
readiness picture; records remaining full release-gate blockers), `Phase6CrossNetworkAndSharedTransportChecklist_2026-04-13.md`
(code-side done; canonical cross-network + extended-soak evidence still to regenerate).

**Active plans and backlogs (selected — full list in the live file):**
`LinuxVmHostPlan_2026-07-14.md` (companion doc §5.6 — the `ubuntu-kvm-1` host), the node-role design
docs above, `CrossNetworkRemoteExitNodePlan_2026-03-16.md`, `CrossPlatformSecurityGapRemediationPlan_2026-03-05.md`,
`DiagnosticFunctionsRoadmap.md`, `HeterogeneousLiveLabEvidence_2026-04-28.md`,
`LinuxUserspaceSharedLiveLabReadinessDelta_2026-04-02.md`, `MagicDnsSignedZoneSchema_2026-03-09.md`,
`OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md`, `RustNativeMultiPlatformOrchestratorPlan_2026-04-28.md`,
the VM Lab Capability trio (`Cookbook`/`ReportingPlan`/`Sources`, all `2026-04-14`),
`WindowsExitAndRelayDeltaPlan_2026-05-10.md`, `WindowsExitNodeRunbook_2026-06-04.md` (how to run +
prove a successful active full-tunnel Windows exit — the ONLY remaining gate is a WinNAT-capable
guest, i.e. `ubuntu-kvm-1`), `WindowsLabVmStabilityAndSessionModel_2026-04-30.md`,
`WindowsLiveLabReadinessPlan_2026-05-31.md`, `WindowsUtmTransportArchitecture_2026-04-30.md`,
`WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md`, `WindowsWorkingNodePlan_2026-04-17.md`,
`MacosUserspaceSharedBackendPlan_2026-05-08.md`, `OvernightAutonomousBugHuntProposal_2026-06-08.md`
(the "Overnight Autonomous Verified-Plane March" v2 design — see companion doc §14's journal digest
for its v3/actual-execution successor pattern that's been running since), `ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md`,
`RustyfinExtensionTrustPlan_2026-05-10.md`, `RustynetComparativeVpnExploitCoverage_2026-03-14.md`,
the security-audit trio (§15 above), `FullRepoAnalysis_2026-05-24.md` (66 findings, 9-agent two-pass
review), `TestCoverageImprovementPlan_2026-05-24.md`, `SerializationFormatHardeningPlan_2026-03-25.md`,
`ShellToRustMigrationPlan_2026-03-06.md`, `StartShOperatorUxRustMigrationPlan_2026-05-24.md` (includes
ready-to-paste reference Rust ports of the remaining shell logic), the UDP-hole-punching trio
(`AndRelayTraversalPlan`/`HP2IngestionPlan`/`ImplementationBlueprint`, all `2026-03-07`), and the two
"SPECULATIVE R&D — UNSCHEDULED" Fable-5 deep-dives (`FableForkConsistentMembershipTransparency_2026-07-01.md`,
`FableIntelligentSystemsProposals_2026-07-01.md`) — explicitly NOT in-flight work, not in the
live-lab acceptance matrix, read only if researching those specific topics.

**Active lab assets:** `UTMVirtualMachineInventory_2026-03-31.md` (VM list, SSH key fingerprints,
probe-and-recover runbook), `../LiveLabRunMatrix.md` + the two CSVs (aggregate run ledger — see
companion doc §5.6/R11 for the two-ledger split), `vm_lab_inventory.json` (VM topology — companion doc
§5.6 has the live snapshot), and several dated JSON evidence files (rule: these are point-in-time,
add a new dated file for new evidence, never edit one in place).

═══════════════════════════════════════════
18) SUB-AGENT DELEGATION — MODEL-TIERED, FOR ANY TASK IN THIS REPO (not just the live-lab loop)
═══════════════════════════════════════════
You (the agent reading this doc) are most likely running as Sonnet. When a task is too large for one
pass, or benefits from parallelism, or needs a second trusted opinion, delegate to a Claude sub-agent
rather than doing everything inline — but pick the model tier deliberately instead of defaulting to
one for everything:

- **Sonnet sub-agent** for well-scoped, low-ambiguity work: verifying a specific claim against the
  real code ("does fn X actually do Y — cite file:line"), fetching/summarizing a bounded set of
  files, or a mechanical patch whose shape already matches an established pattern elsewhere in the
  codebase. Cheap enough to run several concurrently.
- **Opus sub-agent** for genuinely hard work: anything touching crypto, trust-state, the
  privileged-helper boundary, or policy/ACL evaluation (§8's controls catalog); a multi-file
  root-cause investigation where the cause isn't known yet (as opposed to a fix whose shape is
  already clear); adversarial review of a patch before it lands; a design/architecture call not
  already resolved by precedent. Reserve the expensive tier for where a mistake is expensive.
- **You always stay the reviewer of record**, whichever tier did the work — read every diff, re-run
  gates yourself, verify security properties yourself. Delegating the WORK is fine; delegating the
  JUDGMENT is not.
- **Feed a sub-agent this very doc** (`rustynet_repo_context_prompt.md`) at the start of its prompt —
  "Read rustynet_repo_context_prompt.md first for full repo context" — whenever its task needs more
  grounding than one or two named files give it. A fresh sub-agent has none of your conversation
  history; this is the cheapest way to give it the same footing you have. Skip it for a genuinely
  trivial single-file fetch.
- Use `isolation: "worktree"` on the `Agent` tool call whenever more than one sub-agent will patch
  code concurrently, so their edits can't collide on the same working tree.

**If you are running the live-lab loop specifically**, the fuller version of this policy — with a
task-shape → model-tier table and concrete `Agent` call examples — lives in the companion
`rustynet_live_lab_loop_prompt.md` §8. That doc also has a stricter rule worth knowing even outside
the loop: never feed a sub-agent the live-lab-loop doc itself unless it is actually driving the loop
— it's operating doctrine for one job, not general repo context.
