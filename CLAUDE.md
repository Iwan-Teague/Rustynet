# Rustynet Agent Operating Contract

Use this file as mandatory execution guidance for AI implementation agents working in this repository.

`AGENTS.md` and `CLAUDE.md` are intentionally mirrored. Keep them aligned.

## 1) Mission
- Build Rustynet to production-grade quality.
- Keep security as the first priority.
- Keep architecture Rust-first and transport-backend modular.
- Prefer code, tests, gates, and evidence over design-only churn.

## 2) Read Order and Source of Truth
When documents disagree, apply this precedence:
1. `documents/Requirements.md`
2. `documents/SecurityMinimumBar.md`
3. The active scope document for the task
4. Supporting design docs
5. `README.md` and operational runbooks

Read in this order before touching code:
1. `AGENTS.md`
2. `CLAUDE.md`
3. `README.md`
4. `documents/README.md`
5. `documents/Requirements.md`
6. `documents/SecurityMinimumBar.md`
7. The active scope document
8. Relevant runbooks under `documents/operations/`

Current primary execution ledgers:
- `documents/operations/active/CrossPlatformRoleParityPlan_2026-06-21.md` — **RELEASE-BLOCKING COMPLETENESS MANDATE.** Rustynet cannot be called complete until **every node role + capability (client, admin, anchor, exit, blind_exit, relay, +nas/llm) works and is LIVE-LAB-PROVEN on macOS AND Windows, not just Linux.** Linux is the done reference; macOS/Windows must reach full per-role parity, each role proven live in the lab. This doc is the single source of truth for that gap (live-proven status matrix per role × OS, the per-role × per-OS live-lab acceptance matrix, known blockers, and the parity Definition of Done). No OS may be a capability limiter.
- `documents/operations/active/CrossPlatformRoleParityRoadmap_2026-06-22.md` — the execution roadmap that operationalizes the parity mandate: remaining work + effort per mac/win role cell, the ordered implementation program (admin → blind_exit → role-transitions → relay-lifecycle → anchor-live), file-by-file plans, the FAIL-LOUD live-stage spec (live result = stage status; no dry-run-as-pass), and the optimized concurrent Windows+macOS test pipeline + all-on-`main` workflow. Builds on the ParityPlan (status) + EfficiencyPlan (primitives).
- `documents/operations/active/LiveLabExecutionEfficiencyPlan_2026-06-20.md` — the operating method for the same-LAN "drive defects to zero" live-lab loop: setup/run split, per-node `rebuild_nodes`, single-stage wrapper re-run, the mandatory periodic full-validation gate, and the never-idle parallel-work protocol. Follow this while iterating Linux→macOS→Windows→cross-OS.
- `documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md` for the cross-network dataplane track (D2-D13): peer-distributed coordination, home-server-as-zero-ingress-relay, uPnP/IPv6/ICE, enrollment-token onboarding, service-hosting roles (nas, llm). Source of truth for "what are we building and why" when working on traversal, relay, gossip, enrollment, or cellular reliability.
- `documents/operations/active/CrossNetworkSubstrateIntegrationSpec_2026-06-21.md` — focused integration spec to make the cross-network live-lab stages actually run (substrate↔validator mapping: netns NAT-matrix gate, vxlan SSH e2e, slirp cross-OS smoke; orchestrator wiring + phased plan X1–X4).
- `documents/operations/active/ServiceHostingRolesRoadmap_2026-06-11.md` — top-level program roadmap for the `nas` + `llm` service-hosting roles (D13): document set, milestones M0–M6, dependency graph, gate checklist, and status tracker. Start here for the service-hosting-roles program.
- `documents/operations/active/MasterWorkPlan_2026-03-22.md` for repo-wide remaining work
- `documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md` for traversal, relay, and live-lab readiness (the defects it documents drive D2/D3/D4 in the dataplane execution plan)

Current lab-reference assets:
- `documents/operations/active/UTMVirtualMachineInventory_2026-03-31.md` (includes probe-and-recover runbook for unsticking lab guests whose nft killswitch is blocking SSH after a network reconfig)
- `documents/operations/active/vm_lab_inventory.json`
- `scripts/vm_lab/probe_and_recover_local_utm.sh` — call before retrying a failed orchestrator run when one or more lab VMs show TCP/22 timeout but are visible in `arp -a`
- `documents/operations/LiveLabRunMatrix.md` and `documents/operations/live_lab_run_matrix.csv` — standard live-lab wrappers append a row automatically; verify the row exists after every run or focused live-lab stage used as evidence, including commit, dirty state, report directory, OS/role/stage statuses, node identity per role, and regression reference when applicable

Rules:
- If ambiguity exists, choose the strictest secure practical default and document that choice.
- Never weaken a higher-precedence requirement.
- Standalone prompt documents are not part of the repository source of truth. Use the active ledgers, runbooks, and index files instead.

## 3) Non-Negotiable Engineering Constraints
- Rust-first codebase. Non-Rust only for unavoidable OS integration boundaries.
- No custom cryptography and no custom VPN protocol invention in production paths.
- WireGuard must remain an adapter behind stable backend abstractions and be easy to replace.
- No WireGuard-specific leakage into protocol-agnostic control, policy, or domain crates.
- Default-deny policy is mandatory across ACL, routes, and trust-sensitive flows.
- Fail closed when trust/security state is missing, invalid, stale, or unavailable.
- Do not defer in-scope requirements behind TODO/FIXME/placeholders in completed deliverables.
- Enforce one hardened execution path per security-sensitive workflow. No runtime fallback, downgrade, or legacy branch in production paths.

## 4) Security Baseline Requirements
- Enforce signed control/trust state validation before mutation.
- Enforce anti-replay and rollback protection where state freshness matters.
- Enforce strict key custody behavior:
  - use OS-secure key storage when available
  - otherwise use encrypted-at-rest fallback with strict permissions and startup permission checks
- Never log secrets or private key material.
- Preserve privileged-boundary hardening: argv-only exec for helpers, strict input validation, no shell construction with untrusted values.
- Preserve tunnel and DNS fail-closed behavior in protected modes.
- During shell-to-Rust migration, remove superseded shell implementations from active paths. Wrappers may only dispatch to the Rust command and must fail closed on error.

Each implemented security control must include:
1. an enforcement point in code
2. a verification method such as a unit test, integration test, negative test, or gate check

## 5) Required Working Style
- Before coding, read the relevant docs in precedence order.
- Build a concrete checklist from the scope requirements.
- Implement in small, verifiable increments.
- Run the closest relevant tests and gates during implementation, not only at the end.
- Keep the owning ledger or work document current. Do not maintain a hidden private checklist that diverges from repository state.
- Keep documentation synchronized with implementation changes.
- Remove dead links, stale index entries, and prompt-only guidance when you find them.

## 6) Documentation Rules
- `documents/README.md` is the top-level map of the docs tree.
- `documents/operations/README.md` is the operations/runbook map.
- `documents/operations/active/README.md` is the active-work map.
- If you add, remove, rename, archive, or materially repurpose docs, update the relevant index file in the same change.
- If a document becomes historical rather than active, move or classify it honestly.
- Do not reintroduce standalone prompt documents; keep execution guidance in the active ledgers themselves. **Exception — `generic_rustynet_prompt.md`** (repo root): a deliberately-kept, operator-sanctioned reusable autonomous-loop prompt template. It is NOT source-of-truth guidance (the active ledgers are) and must NOT be deleted as a stale prompt doc; keep it current with the tooling it references (e.g. the DeepSeek MCP functions).

## 7) Validation and CI Gates
Run these as mandatory quality gates for substantial work:
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo check --workspace --all-targets --all-features`
- `cargo test --workspace --all-targets --all-features`
- `cargo audit --deny warnings`
- `cargo deny check bans licenses sources advisories`

Fast-fail convenience runner (recommended for local iteration):
- `cargo run -p rustynet-xtask -- gates` runs fmt → check → clippy → test in
  dependency order, stops at the first failure, streams output live, and wraps
  each stage in a timeout watchdog (kills the whole process group and prints the
  tail on a hang). Add `--skip-test` to gate without the slow test stage, or
  pass a cargo scope such as `-p rustynet-cli`. Per-stage timeouts are
  overridable via `XTASK_{FMT,CHECK,CLIPPY,TEST}_TIMEOUT` (seconds). The
  individual commands above remain the authoritative gate definitions.

Run scope-specific scripts when present:
- `./scripts/ci/phase9_gates.sh`
- `./scripts/ci/phase10_gates.sh`
- `./scripts/ci/membership_gates.sh`
- any active-phase gate script required by the scope document

If any gate fails:
1. stop phase progression
2. fix the root cause, not the symptom
3. re-run the impacted gates
4. record failure, fix, and proof in the relevant progress document when scope requires it

## 8) Architecture Boundary Rules
- Keep domain models and policy evaluation transport-agnostic.
- Keep backend-specific behavior in backend adapter crates.
- Expose capabilities via backend interfaces rather than leaking backend types.
- Maintain deterministic, testable state transitions for trust-sensitive systems.

## 9) Definition of Done
Work is complete only when all are true:
- in-scope requirements are implemented end-to-end
- security minimum bar controls are satisfied for that scope
- all mandatory gates pass, or the remaining blocker is explicitly documented and outside the claimed completion
- required artifacts exist and validate
- no unresolved in-scope blockers remain
- no TODO/FIXME/placeholders remain in completed deliverables

## 10) Common Patterns & How To Apply The Rules

This section translates the abstract rules above into concrete code patterns.
Agents should internalize these — they are the difference between code that
passes review and code that gets rejected.

### 10.1 Fail-Closed Pattern

Rule §3: "Fail closed when trust/security state is missing, invalid, stale,
or unavailable."

**Wrong:**
```rust
let state = load_trust_state().unwrap_or_default();
```

**Right:**
```rust
let state = match load_trust_state() {
    Ok(s) => s,
    Err(e) => {
        tracing::error!(%e, "trust state unavailable; failing closed");
        return Err(AdapterError::TrustStateUnavailable);
    }
};
```

Every path that reads trust/security state must handle the None/Err case
explicitly and return an error — never default, never silently continue.

### 10.2 Error Handling — No unwrap() or expect() in Production Paths

Rule §3: "One hardened execution path per security-sensitive workflow."

unwrap() and expect() are panics. In security-sensitive code, panics are
denial-of-service vectors. Use proper error propagation:

**Wrong:**
```rust
let key = load_key().unwrap();
let sig = verify(&key, &data).expect("signature verification failed");
```

**Right:**
```rust
let key = load_key().map_err(|e| AdapterError::KeyLoadFailed(e.to_string()))?;
let sig = verify(&key, &data).map_err(|e| AdapterError::SignatureInvalid(e.to_string()))?;
```

unwrap() is acceptable ONLY in:
- Unit tests
- Build scripts (build.rs)
- One-shot CLI entry points (not library code)
- Cases where the invariant is locally provable AND a comment explains why

### 10.3 Backend Abstraction Boundary

Rule §8: "Keep domain models and policy evaluation transport-agnostic.
Keep backend-specific behavior in backend adapter crates."

**Wrong:** importing wireguard types in rustynet-control or rustynet-policy.

**Right:** domain crates (control, policy, dns-zone) use abstract types.
Backend crates translate between abstract types and concrete WireGuard types.

Test with: scripts/ci/check_backend_boundary_leakage.sh

### 10.4 Default-Deny Always

Rule §3: "Default-deny policy is mandatory across ACL, routes, and
trust-sensitive flows."

**Wrong:** empty ACL → allow. Empty membership → allow. Missing context → allow.

**Right:** empty/missing/malformed → deny. The policy evaluator starts from
a deny-all posture and only adds allows for explicitly present entries.

When adding a new policy or ACL path, the first test you write should be:
"empty input produces deny."

### 10.5 Signed State — Verify Before Apply

Rule §4: "Enforce signed control/trust state validation before mutation."

**Wrong:** read a bundle, apply it, then check the signature.

**Right:** verify signature FIRST, check epoch/replay-watermark SECOND,
apply THIRD. Never apply unsigned or stale state.

### 10.6 Secrets Hygiene

Rule §4: "Never log secrets or private key material."

- Use tracing::Span with fields marked for redaction.
- Never Debug-print a type containing key material unless its Debug impl
  explicitly redacts.
- Test with: scripts/ci/secrets_hygiene_gates.sh

### 10.7 Role Transitions Are Not Just String Changes

When implementing a role transition, the side-effects matter more than the
role field. See get_role_transition in the MCP repo-context server.

Key rules:
- Adding serves_relay: deploy service BEFORE emitting signed bundle
- Removing serves_relay: undeploy service BEFORE revocation bundle
- Exit NAT: tear down BEFORE removing capability (residue = release-blocker)
- blind_exit is irreversible — requires factory reset
- All transitions emit append-only audit log entries

### 10.8 Test Location and Naming

- Unit tests: inline, #[cfg(test)] mod tests { ... }
- Integration tests: crates/<name>/tests/<scenario>.rs
- Names: descriptive_snake_case (e.g. gossip_three_peer_mesh)
- Every security control: 1 enforcement point + 1 verification test

### 10.9 Working With The Live Lab

- Check lab state first: ops vm-lab-discover-local-utm-summary
- If VMs stuck (SSH timeout): scripts/vm_lab/probe_and_recover_local_utm.sh
- Never hand-edit vm_lab_inventory.json — use --update-inventory-live-ips
- After every evidence run, verify the row in live_lab_run_matrix.csv

### 10.10 Commit Hygiene

- Small, verifiable increments — one logical change per commit
- Commit messages: imperative mood, what AND why
- Never commit generated files, build artifacts, or secrets
- Run at minimum: cargo fmt --all -- --check && cargo check -p <crate>

## 11) Repository Map & Codebase Structure

Rustynet is a Cargo workspace (`edition = "2024"`, `resolver = "2"`,
`unsafe_code = "forbid"` workspace-wide). For a symbol-level reference (key
types, traits, and the files they live in), read `documents/CODE_MAP.md` — it is
the authoritative map and should be kept in sync when types move.

### 11.1 Top-Level Layout
- `crates/` — all workspace crates (see §11.2).
- `third_party/` — vendored path deps: `boringtun` (userspace WireGuard),
  `rustynet-tun` (TUN device), `rustynet-alloc-meter` (allocation accounting).
  Treat as adapters behind the backend boundary; do not leak their types
  upward (§8, §10.3).
- `documents/` — source-of-truth docs. `Requirements.md` and
  `SecurityMinimumBar.md` are top-precedence; `CODE_MAP.md` is the code map;
  `operations/active/` holds the live execution ledgers (§2); `operations/done/`
  and `archive/` hold history.
- `scripts/` — operational + CI tooling, grouped by area: `ci/` (gate scripts),
  `vm_lab/` (UTM lab helpers incl. `probe_and_recover_local_utm.sh`),
  `bootstrap/`, `dev/`, `e2e/`, `fuzz/`, `launchd/`, `systemd/`, `windows/`,
  `perf/`, `release/`, `operations/`, `mcp/`. Many `ci/*.sh` scripts are thin
  wrappers over a Rust binary of the same name in `rustynet-cli/src/bin/` — the
  Rust binary is the real implementation (§4 shell-to-Rust migration rule).
- `fuzz/` — `cargo-fuzz` targets (`ipc_parse_command`, `membership_decode_state`,
  `membership_decode_signed_update`). Its own `[workspace]`.
- `mcp/` (`mcp.json`) and `tools/skills/` — MCP server config and the
  `rustynet-security-auditor` skill (attack catalog, audit checklist, lab
  playbooks) used for security review.
- `profiles/live_lab/` — live-lab impairment/topology profiles.
- `artifacts/` — generated evidence/SBOM/provenance outputs (do not hand-edit).
- `start.sh` — interactive setup/menu wizard; `rust-toolchain.toml` pins the
  toolchain; `deny.toml` configures `cargo deny`.

### 11.2 Workspace Crates (layered per CODE_MAP.md)

Domain layer (transport-agnostic — never import a backend or WireGuard type
here, §8/§10.3):
- `rustynet-control` — membership bundles, enrollment tokens, roles/capabilities,
  role transitions, gossip, replay watermarks. The core trust-state crate.
- `rustynet-policy` — ACL + policy evaluation (default-deny, §10.4).
- `rustynet-dns-zone` — Magic DNS signed-zone schema.
- `rustynet-crypto` — signing, key types, key custody primitives.
- `rustynet-local-security` — local ACL verifiers / privileged-boundary checks.
- `rustynet-sysinfo` — OS detection, interface enumeration.

Daemon + services layer:
- `rustynetd` — the node daemon: WireGuard management, dataplane engine, STUN,
  gossip runtime/transport, ICE, enrollment, killswitch. Binary `rustynetd`.
- `rustynet-relay` — frame forwarding for the zero-ingress relay role. Binary
  `rustynet-relay`.
- `rustynet-nas` — `nas` service-hosting role (tunnel-only storage). Binary
  `rustynet-nas`.
- `rustynet-llm-gateway` — `llm` service-hosting role (identity-from-tunnel
  gateway in front of a loopback inference engine). Binary
  `rustynet-llm-gateway`.

Backend abstraction layer (the WireGuard adapter boundary, §3/§8):
- `rustynet-backend-api` — the `Backend` trait and abstract types. No backend
  internals.
- `rustynet-backend-wireguard` — kernel WireGuard adapter (wraps `boringtun` /
  `rustynet-tun`).
- `rustynet-backend-userspace` — userspace (boringtun) backend.
- `rustynet-backend-stub` — deterministic test stub backend.

Platform + UX + tooling layer:
- `rustynet-windows-native` — Windows-specific integration (WFP, DPAPI, named
  pipes). The OS-boundary exception to Rust-first purity.
- `rustynet-operator` — operator wizards / config (`rustynet operator menu`).
- `rustynet-cli` — the main `rustynet` binary (`default-run = "rustynet-cli"`):
  `ops`, `vm-lab`, live-lab orchestrator, role/anchor/llm subcommands. Its
  `src/bin/` also holds the large family of `live_*`, `*_gates`, `phase*`, and
  `check_*` evidence/gate binaries that the `scripts/ci/` wrappers dispatch to.
- `rustynet-mcp` — MCP servers: `rustynet-mcp-repo-context`,
  `rustynet-mcp-gate-runner`, `rustynet-mcp-lab-state`.
- `rustynet-xtask` — the `xtask` dev runner (see §7 / §12).

### 11.3 Release Profile Note
`[profile.release]`/`[profile.bench]` enable thin LTO and pin
`codegen-units = 1` for the hot crypto/dataplane crates (`boringtun`,
`rustynet-backend-wireguard`, `rustynet-relay`). This is a perf tuning, not a
semantic change — keep it only while the perfprobe/criterion numbers justify the
build-time cost.

## 12) Quick Command & Workflow Reference

Authoritative gate definitions live in §7. This section is the fast-path map.

### 12.1 Build & Iterate
- Scoped check while editing: `cargo check -p <crate>` then
  `cargo fmt --all -- --check`.
- Fast-fail local gate run: `cargo run -p rustynet-xtask -- gates`
  (fmt → check → clippy → test, stops at first failure, timeout watchdog). Add
  `--skip-test` or a `-p <crate>` scope; override stage timeouts via
  `XTASK_{FMT,CHECK,CLIPPY,TEST}_TIMEOUT` (seconds).
- Full workspace test: `cargo test --workspace --all-targets --all-features`.

### 12.2 Boundary & Security Gates (run for relevant scopes)
- Backend leakage: `scripts/ci/check_backend_boundary_leakage.sh` (§10.3).
- Secrets hygiene: `scripts/ci/secrets_hygiene_gates.sh` (§10.6).
- Supply chain: `cargo audit --deny warnings` and
  `cargo deny check bans licenses sources advisories`.
- Phase/role/membership scopes have dedicated `scripts/ci/*_gates.sh` wrappers;
  run the one matching your scope document.

### 12.3 Live Lab
- Inventory summary first: `rustynet ops vm-lab-discover-local-utm-summary
  --inventory documents/operations/active/vm_lab_inventory.json`.
- If a guest is stuck (SSH timeout but visible in `arp -a`):
  `scripts/vm_lab/probe_and_recover_local_utm.sh` before retrying.
- Never hand-edit `vm_lab_inventory.json` — refresh with
  `--update-inventory-live-ips`.
- After every evidence run, verify the appended row in
  `documents/operations/live_lab_run_matrix.csv` (§2, §10.9).

### 12.4 Operator UX
- Interactive wizard: `./start.sh`.
- Rust-native operator menu: `rustynet operator menu`.

### 12.5 Research & Triage — the DeepSeek MCP (`rustynet-mcp-deepseek`)

DeepSeek is the **research / triage / summarizing layer**: offload the
token-heavy *reading* to it and reserve your own (expensive) context for the
code change, the security call, and the live lab. If you catch yourself reading
a long log / journal / diff / doc just to understand it, hand it to DeepSeek
first and act on the distilled output.

Seven tools (`mcp__rustynet-deepseek__*`). The first four take `prompt`, optional
`context`, and `model`:
- `deepseek_read` — analysis / review / second opinion / risk ID (read-only).
- `deepseek_write` — generate boilerplate / test scaffolds / doc drafts.
- `deepseek_read_write` — analyze existing content, then generate (review-then-fix).
- `deepseek_agent` — **READ-ONLY autonomous agent that GROUNDS against the actual
  local repo + UTM lab.** Drives a tool-calling loop over ~20 confined read-only
  tools (read_file / grep / find_definition / git / find_files + lab_inventory /
  lab_run_status / lab_stage_log / lab_report_grep / lab_guest_exec /
  utm_vm_status / lab_node_reachable / …) and answers with cited evidence + an
  audit trace. **The three proxies see only what you paste; the agent verifies a
  claim against reality** ("does this fn really do X?", "did that stage fail
  because Y?", "is this node reachable?"). Prefer it whenever you want DeepSeek
  to check the real code/lab, not opine on a pasted snippet.

The remaining three are the live-lab family. The **loop driver** you normally call:
- `deepseek_lab_run` — **one call runs the WHOLE pipeline.** Give it an `area`
  (e.g. "macOS relay") + optional selectors (`macos`/`windows`/`macos_vm`/
  `windows_vm`/`exit_vm`/`client_vm`/`rebuild_nodes`); a DETERMINISTIC worker
  launches the hardened orchestrator (NO LLM in the deploy/monitor path), waits,
  and on FAILURE runs the rigid triage below. Async: returns a `job_id`, poll
  `deepseek_live_lab_result`. Singleton by default; `allow_concurrent: true` +
  disjoint guests (a separate `exit_vm` per run) runs the macOS↔Windows pipeline
  (≤3 overlapping). `dry_run` is a fast wiring check. On a green run, ZERO LLM
  calls — you just get PASS + evidence. To drive a FOCUSED mac/win role cell (not
  just a comprehensive run), pass a role-platform selector — `exit_platform` /
  `relay_platform` / `anchor_platform` / `blind_exit_platform` (each
  `linux|macos|windows`), or `macos_promote_exit: true` (+ `entry_vm` in the
  Option-B exit topology) — to ELECT a mac/win node into that role so the cell
  runs live instead of skipping.
- `deepseek_live_lab` — **the rigid, non-negotiable failure-triage pipeline** on a
  failure you ALREADY have (hand it `target` + `failure_context`). Three grounded
  read-only sub-agents in fixed order — v4-flash research (why/where/what) →
  v4-flash verify-every-claim-against-the-repo/lab → v4-pro at MAX reasoning
  re-verify + judge-the-best-fix — into ONE evidence-cited report (root cause,
  file:line, suspected fix). Async (job_id → poll). `deepseek_lab_run` calls this
  internally on failure; call it directly when you already have the evidence.
- `deepseek_live_lab_result` — poll either of the above by `job_id` (non-blocking:
  the report when done, else "still running Ns").

After a lab-verified fix, the **docs-sync proposer**:
- `deepseek_doc_sync` — **PROPOSE-ONLY, READ-ONLY docs-sync.** Give it
  `change_summary` (REQUIRED: what was fixed/patched/verified) + optional `commit`
  / `evidence` (the verifying lab run id / run-matrix row / stage) / `doc_hints`
  (likely-affected docs, e.g. "CrossPlatformRoleParityPlan") / `model` / `max_steps`.
  It runs the SAME grounded agent loop as `deepseek_agent` but on the
  **repo-reads-only** subset (read_file/list_dir/grep/find_files/find_definition/
  find_references + read-only git — NO lab/guest/cargo tools): it reads the CURRENT
  docs (active ledgers, CODE_MAP, README/AGENTS/CLAUDE, the doc indexes, the
  run-matrix) and returns a STRUCTURED list of exact docs-only edits
  (`file`/`old_string`/`new_string`/`rationale`, each copy-paste-applicable by exact
  string replacement) plus a "considered, no change" coverage list. Docs-only
  (`documents/**` + root `README.md`/`AGENTS.md`/`CLAUDE.md`); enforces the
  AGENTS.md↔CLAUDE.md mirror + index-sync, and never invents evidence/status/dates/
  SHAs. It writes NOTHING — a human applies the edits. Async like the others:
  returns a `job_id`; poll `deepseek_live_lab_result` for the proposal. UNTRUSTED
  output — review before applying.

No live-lab step writes the repo, runs gates, or makes the security call — DeepSeek
proposes, you verify each cited claim against the real code and dispose.

Use it for: digesting CI logs / daemon journals / nft-pf dumps / large diffs;
per-finding root-cause triage (one call each); researching unfamiliar errors +
platform quirks (WFP / PF-launchd / nft / WireGuard); proactively hunting latent
bugs ("given this crate, list the 10 most likely fail-open paths / missing
platform-cfg cases"); drafting test scaffolds; and — before committing a
security-sensitive patch — 3–5 concurrent "REFUTE this patch" cross-checks
(disagreement = dig deeper first).

Model: `model: "flash"` (deepseek-v4-flash — fast, cheap; the DEFAULT, fan
liberally and concurrently for breadth). `model: "pro"` (deepseek-v4-pro at max
reasoning effort — chain-of-thought, slow; reserve for genuinely hard multi-step
root-cause / protocol-logic reasoning where flash keeps giving conflicting
answers).

**Hard limits — DeepSeek output is UNTRUSTED.** It never makes the security call,
never writes the repo, never runs gates. It *proposes*; you verify against the
real code and *dispose*. A grounded "DeepSeek-verifies-DeepSeek" chain (flash
proxy finds candidates → `deepseek_agent` confirms each against the repo/lab → you
do the final security check) cuts false positives but **certifies nothing** — for
any claim driving a security or code change, YOUR verification against the real
code stays mandatory. If the server is down, proceed without it.

Operational: the servers run pre-built binaries at `bin/rustynet-mcp-*` (config in
`mcp/mcp.json`). If `deepseek_agent`/`deepseek_live_lab` is absent or stale,
rebuild (`cargo build --release --bin rustynet-mcp-deepseek`) and install via an
atomic **`mv`, NOT in-place `cp`** — the client keeps the running binary mmap'd,
so `cp` truncates it in place and CORRUPTS it (symptom: the server starts but
emits nothing). Use `cp … bin/x.new && mv -f bin/x.new bin/x`. Then reconnect the
server (`/mcp` → reconnect, or restart the client — killing the process does NOT
auto-respawn, and there is no `claude mcp` reconnect subcommand). When you can't
reconnect (e.g. a remote client), drive the freshly built binary **directly over
stdio** instead — `scripts/mcp/drive_deepseek.py --tool <name> --args '<json>'`
spawns the latest binary, does the JSON-RPC handshake, calls the tool, and
auto-polls `deepseek_live_lab_result` for the async run/triage tools, so the
newest tools are reachable with NO client reconnect. The API key resolves from `DEEPSEEK_API_KEY` or
`~/Desktop/deepseek_api.md`; **never commit, log, or write it into the repo or any
artifact.**

## 13) Keeping AGENTS.md / CLAUDE.md In Sync
`AGENTS.md` and `CLAUDE.md` are intentionally byte-for-byte mirrored. Any edit to
one MUST be applied identically to the other in the same change. When you add,
move, or rename a crate, ledger, or top-level directory, update §2/§11/§12 here
(and the mirror) plus `documents/CODE_MAP.md` so the structure map does not drift
from the code.
