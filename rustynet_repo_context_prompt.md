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

═══════════════════════════════════════════
1) MISSION & SCOPE
═══════════════════════════════════════════
Rustynet is a production-grade, security-first Rust mesh VPN — a Cargo workspace
(`edition = "2024"`, `resolver = "2"`, `unsafe_code = "forbid"` workspace-wide). It is being
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

**The docs tree is large (196 files at last count) and actively curated — don't hand-enumerate
it, use the tools built for it:**
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
| `rustynet-backend-api` | The `Backend` trait and abstract types. No backend internals. |
| `rustynet-backend-wireguard` | Kernel WireGuard adapter (wraps `boringtun`/`rustynet-tun`). |
| `rustynet-backend-userspace` | Userspace (boringtun) backend. |
| `rustynet-backend-stub` | Deterministic test stub backend. |

**Platform + UX + tooling layer:**
| Crate | Does |
|---|---|
| `rustynet-windows-native` | Windows-specific integration (WFP, DPAPI, named pipes) — the sanctioned OS-boundary exception to Rust-first purity. |
| `rustynet-operator` | Operator wizards/config (`rustynet operator menu`). |
| `rustynet-advisor` | FIS-0005 role-placement decision support: pure MCDA scorer over per-candidate observations (`rustynet role recommend`). Domain layer; collectors live in the CLI. |
| `rustynet-cli` | The main `rustynet` binary (`default-run = "rustynet-cli"`): `ops`, role/anchor/llm subcommands. **The lab robot — `vm-lab`, the live-lab orchestrator, and the e2e/cross-network/fresh-install `ops` surface — compiles only under the DEFAULT-OFF `vm-lab` cargo feature** (RNQ-17): the shipped release binary carries none of it, CI gates run `--all-features`, lab hosts/guests build with `--features vm-lab`. `src/bin/` also holds the large family of `live_*`, `*_gates`, `phase*`, `check_*` evidence/gate binaries the `scripts/ci/` wrappers dispatch to. |
| `rustynet-mcp` | MCP servers: `rustynet-mcp-repo-context`, `rustynet-mcp-gate-runner`, `rustynet-mcp-lab-state`, `rustynet-mcp-deepseek`. |
| `rustynet-xtask` | The `xtask` dev runner (§10). |
| `rustynet-netns-probe` | LAB TOOLING (not shipped): the Rust-native STUN responder + NAT mapping/filtering probes the `--node` cross-network netns simulator runs on-guest. `std`-only, offline-buildable. STUN wire is byte-pinned to `rustynetd`'s `stun_client.rs`. |
| `rustynet-lab-monitor` | The pixelated TUI live-lab monitor. Excluded from the main workspace; build separately. |

**Dependency chains** (who breaks when you patch the shared crate):
- `rustynet-control` ← `rustynetd`, `rustynet-cli`, `rustynet-operator`, `rustynet-mcp`
- `rustynet-backend-api` ← `rustynet-backend-{wireguard,userspace,stub}` ← `rustynetd`
- `rustynet-policy` ← `rustynetd` (policy eval is daemon-side)
- `rustynet-crypto` ← `rustynet-control`, `rustynetd`, `rustynet-cli`

**CRITICAL BOUNDARY:** domain crates (`control`, `policy`, `dns-zone`, `crypto`) MUST NOT import
backend or WireGuard types. The backend trait lives in `rustynet-backend-api`; all
WireGuard-specific code lives behind it. Violation is blocked by
`scripts/ci/check_backend_boundary_leakage.sh`.

**Release profile note:** `[profile.release]`/`[profile.bench]` enable thin LTO and pin
`codegen-units = 1` for the hot crypto/dataplane crates (`boringtun`,
`rustynet-backend-wireguard`, `rustynet-relay`) — a perf tuning, keep it only while the
perfprobe/criterion numbers justify the build-time cost.

Use `mcp__rustynet-repo-context__get_crate_structure()` and `get_crate_dependencies()` for the
always-fresh version of this table, and `which_crate(symbol_or_concept)` to jump straight to
the owning crate from a symbol or concept name.

═══════════════════════════════════════════
7) KEY DOMAIN TYPES & ROLE TRANSITIONS
═══════════════════════════════════════════
| Type | File | Notes |
|---|---|---|
| `NodeRole` (Client/Admin/Exit/BlindExit/Relay/Anchor/Nas/Llm) | `rustynet-control/src/roles.rs` | 8 roles, used everywhere |
| `Capability` enum | `rustynet-control/src/roles.rs` | Sub-capabilities per role |
| `RoleTransition` | `rustynet-control/src/role_presets.rs` | Transition plan: identity/local-only/signed/blocked/irreversible |
| `MembershipState` | `rustynet-control/src/membership.rs` | Signed membership bundle, peer list, epoch, watermark |
| `SignedUpdate` (enum) | `rustynet-control/src/membership.rs` | Revoke/Restore/RotateKey/SetCapabilities variants |
| `DefaultDenyPolicy` | `rustynet-policy/src/eval.rs` | Default-deny ACL evaluator |
| `Backend` trait | `rustynet-backend-api/src/lib.rs` | Tunnel backend abstraction — WireGuard lives behind it |

**Role transitions are not just string changes — the side effects matter more than the role
field.** Rules (verify against `mcp__rustynet-repo-context__get_role_transition()` or
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
| 4.A | Signed state validation before mutation | `rustynet-control/src/membership.rs` — `verify()` before `apply()` | unit test + live lab |
| 4.B | Anti-replay watermark | `rustynet-control/src/watermark.rs` — reject stale epochs | unit test |
| 4.C | Key custody: OS secure storage or encrypted-at-rest | `rustynet-crypto/src/key_custody.rs` — Keychain/DPAPI or encrypted file + `0o600` | key_custody stage |
| 4.D | No secrets in logs | `rustynetd/src/secret_log_audit.rs` — greps the daemon journal for key material | secrets_not_in_logs stage |
| 4.E | Default-deny ACL | `rustynet-policy/src/eval.rs` — empty/missing → deny | policy_default_deny audit |
| 4.F | Fail-closed on trust state unavailable | `rustynetd/src/phase10.rs` — error on missing state, never default | runtime validation |
| 4.G | One hardened execution path, no runtime fallback | all security paths — no try-or-downgrade | code review |
| 4.H | Privileged helper argv allowlist | `rustynetd/src/privileged_helper.rs` — `validate_request()` | helper_allowlist audit |
| 4.I | `blind_exit` irreversibility | `rustynet-control/src/role_presets.rs` — `preview_next_state()` rejects `blind_exit`→anything | blind_exit_reversal audit |
| 4.J | Enrollment token replay prevention | `rustynetd/src/enrollment_token.rs` — token consumption idempotent | enrollment_replay audit |
| 4.K | Gossip revoked-peer re-admission denial | `rustynetd/src/peer_gossip.rs` — reject bundles from revoked sources | gossip_revoked_readmit audit |
| 4.L | Revoked peer dataplane denial | `rustynetd/src/revoked_peer_denied_audit.rs` — NoopBackend eval | revoked_peer_denied audit |
| 4.M | Membership signature forgery rejection | `rustynetd/src/membership_signature_audit.rs` | signature_forgery audit |
| 4.N | Membership revoke delayed-apply | `rustynetd/src/membership_revoke_audit.rs` — 4 delayed-apply + 2 negative cases | membership_revoke audit |
| 4.O | Hello-limiter flood cap | `rustynet-relay/src/hello_limiter_audit.rs` — DOS-1 | hello_limiter_flood audit |
| 4.P | Runtime ACL integrity | `rustynetd/src/{linux,macos,windows}_runtime_acls.rs` | runtime_acls stage |
| 4.Q | Service hardening | `rustynetd/src/{linux,macos,windows}_service_hardening.rs` | service_hardening stage |
| 4.R | Mesh state integrity | `rustynetd/src/{linux,macos,windows}_mesh_status.rs` | mesh_status stage |

Every control needs at least one unit test + one live-lab stage (except the planned NAS/LLM
roles, which don't have live-lab stages yet). Use
`mcp__rustynet-repo-context__get_security_controls()` and `get_security_findings()` for the
always-fresh version, cross-checked against `documents/SecurityMinimumBar.md` itself.

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

**Fast-fail convenience runner** (recommended for local iteration):
`cargo run -p rustynet-xtask -- gates` runs fmt→check→clippy→test in dependency order, stops at
the first failure, streams output live, and wraps each stage in a timeout watchdog. Add
`--skip-test` to gate without the slow test stage, or `-p <crate>` to scope. Per-stage timeouts
are overridable via `XTASK_{FMT,CHECK,CLIPPY,TEST}_TIMEOUT` (seconds).

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
| `get_crate_structure()` | Per-crate summary: what it does, its layer, its boundary rule |
| `get_crate_dependencies()` | The dependency graph between crates |
| `which_crate(symbol_or_concept)` | Jump from a symbol/concept name to its owning crate |
| `get_platform_support()` | Current per-platform support status |
| `get_requirements()` | `Requirements.md` content, queryable |
| `get_role_transition()` | The role-transition rules (§7 above) |
| `get_security_controls()` | The security controls catalog (§8 above) |
| `get_security_findings()` | Current open security findings |
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
- **Exception — two operator-sanctioned, repo-root prompt templates:** this doc
  (`rustynet_repo_context_prompt.md`) and its companion `rustynet_live_lab_loop_prompt.md`.
  Neither is source-of-truth guidance (the active ledgers are) and neither should be deleted as
  a "stale prompt doc" — keep both current with the architecture, tooling, and MCP functions
  they reference.
- `AGENTS.md` and `CLAUDE.md` are intentionally byte-for-byte mirrored. Any edit to one MUST be
  applied identically to the other in the same change. When a crate, ledger, or top-level
  directory is added/moved/renamed, update §2/§11/§12 there (and the mirror) plus
  `documents/CODE_MAP.md` so the structure map does not drift from the code.
- Remove dead links, stale index entries, and prompt-only guidance when you find them.
