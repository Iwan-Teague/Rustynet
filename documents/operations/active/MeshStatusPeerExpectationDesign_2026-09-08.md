# MeshStatus Peer Expectation Design (QH-81) — 2026-09-08

Status: DESIGN (read-only investigation; no code changed on this branch).
Scope: fix QH-81 — the MeshStatus validator cannot express a peer expectation at all.
Companion evidence: `MeshStatusEvidenceReview_2026-09-08.md` (the failed orchestrator-side attempt and its revert).

## 1. The defect, precisely

The daemon persists **route CIDRs in a field named `peer_ids`**:

- `crates/rustynetd/src/daemon.rs:10302-10317` — `persist_state` builds `SessionStateSnapshot { peer_ids: self.advertised_routes.iter().cloned().collect::<Vec<_>>() }`. The field's content is `advertised_routes` (CIDR strings, e.g. `10.7.0.0/24`).
- `crates/rustynetd/src/resilience.rs:36-38` — `pub struct SessionStateSnapshot { pub peer_ids: Vec<String> }`; serialized as the `peer_ids=` key/value line (`:107`, `:110`), parsed at `:164`/`:173`, **missing key = `ResilienceError::InvalidFormat` (fail-closed, `:213`)**.
- All three platform collectors copy `snap.peer_ids` verbatim into the report: `linux_mesh_status.rs:59`, `macos_mesh_status.rs:145`, `windows_mesh_status.rs:110`. So the report field `peer_ids` contains CIDRs on every platform.
- The expectation check itself **already exists and is correct mechanics**: `windows_mesh_status.rs:179-182` — for each expected id, `if !peer_ids.iter().any(|p| p == expected) { error }`; same evaluation path on macOS (`macos_mesh_status.rs:211`) and Linux (`linux_mesh_status.rs:78`). Only the data is wrong.
- The orchestrator never emits an expectation: `crates/rustynet-cli/src/vm_lab/orchestrator/stage/validate_runtime.rs:54-76` — `probe_expectations` for `MeshStatus` produces only `["--max-age-seconds", …]`. The `rustynetd` CLI probe **already parses `--expected-peer-id`** (`crates/rustynetd/src/main.rs:1001/:1625/:1839` collect, `:1047/:1669/:1899` pass into options), so orchestrator-side emission has zero CLI-plumbing cost.
- The daemon **already holds real node ids**: `crates/rustynetd/src/phase10.rs:8794: pub fn managed_peer_ids(&self) -> Vec<NodeId>` (same peer table as `managed_peer_latest_handshake_unix` `:8541` and `current_peer_endpoints` `:8528`, which the live-handshake poll consumes). Gossip-derived alternatives exist (`gossip_runtime.rs:890`, `:431`) but the phase10 peer table is the one whose liveness the lab already trusts.

The orchestrator-side rejection of the empty case (commit `d944c700`) was correctly reverted: on a ≥2-node run the condition was unsatisfiable **by construction** — the daemon can never honestly publish node ids in `peer_ids`, so no expectation could ever match. The data model is wrong, not the check.

## 2. Decision

**Rename to honest names and add the real thing.** Four coordinated changes, one logical change:

1. **`SessionStateSnapshot`** (`resilience.rs`): `peer_ids: Vec<String>` → `advertised_route_cidrs: Vec<String>` (key `advertised_route_cidrs=`), and add a **required** `managed_peer_ids: Vec<String>` (key `managed_peer_ids=`) holding node-id strings.
2. **`daemon.rs`**: `persist_state` (`:10302-10317`) writes `advertised_route_cidrs` from `self.advertised_routes` and `managed_peer_ids` from `managed_peer_ids()` (`phase10.rs:8794`). `restore_state` (`:10407-10415`) restores `advertised_route_cidrs` into `self.advertised_routes`; `managed_peer_ids` is **not restored** — the WireGuard peer table is rebuilt from membership/live state, and the snapshot value is status evidence only.
3. **Collectors** (all three): report field `peer_ids` → `advertised_route_cidrs` (verbatim copy, unchanged); **new report field `managed_peer_ids`** copied verbatim from the snapshot. The expectation check evaluates expected ⊆ `managed_peer_ids` on all three platforms (Windows mechanics at `:179-182` generalize unchanged).
4. **Orchestrator** (`validate_runtime.rs:65-76`): `probe_expectations` for `MeshStatus` emits `--expected-peer-id <id>` once per node in `ctx.node_ids` (`:290`) minus the probed node itself. Single-node runs legitimately emit zero expectations (vacuous pass, documented in the stage doc comment). The live-handshake poll in `mesh_status_validation` **stays** — it proves handshake *recency*; this fix proves *membership presence*. They answer different questions.

Why not the alternatives:

- **Keep `peer_ids` name, change content to node ids**: the snapshot field is load-bearing — `restore_state` (`daemon.rs:10407`) reads it back into `advertised_routes`. Changing content under the old name silently corrupts restore (node ids land in the route table). Rejected.
- **Add-only (leave `peer_ids`=CIDRs, add `managed_peer_ids`)**: perpetuates a field whose name promises node ids and delivers CIDRs — the exact lie QH-81 files. Every future reader pays the confusion tax. Rejected.
- **Report-only fix without a snapshot change**: the collectors are probe-mode binaries that read the persisted snapshot file (`linux_mesh_status.rs` tests `:187-282` load key/value text via `load_session_snapshot`); they have no other channel to daemon state. A snapshot key is the only honest path. (Other IPC channels: UNVERIFIED — none observed in the three collectors.)

## 3. Wire/format cost and versioning

- **MeshStatus report JSON**: two field renames (`peer_ids`→`advertised_route_cidrs`) plus one additive field (`managed_peer_ids`). Consumers are all in-repo (orchestrator validator + focused runners) and updated in the same change — no version bump needed; the report is generated and consumed within one commit boundary.
- **Session snapshot file** (on-disk, unversioned key/value text, `resilience.rs`): a rename (`peer_ids=`→`advertised_route_cidrs=`) plus an additive **required** key. Parse behavior: missing required key = `InvalidFormat` (`:213`) — the new schema fails closed on old files. Tolerated-unknown lines (`future_field=value`, `digest=ignored`, `:643`) mean an **old daemon reading a new file** fails closed too (it requires `peer_ids=` which no longer exists). **No dual-read compatibility window** — a dual-read is a legacy branch in a production path, which CLAUDE.md §3 forbids. Consequence: one-time restore failure per node after upgrade. This is OD1 below.

## 4. Fail-closed analysis (mandatory)

- **Absent (old snapshot file, new daemon)**: `advertised_route_cidrs` / `managed_peer_ids` keys missing → `InvalidFormat` at load (`resilience.rs:213` pattern). Restore fails closed. The post-restore daemon posture on load failure is **UNVERIFIED** (whether it refuses to start or starts restricted) — OD1 covers the policy; the parser half is already fail-closed and unchanged.
- **Absent (new daemon, field empty)**: empty `advertised_route_cidrs` is a legitimate state (no routes advertised; `resilience.rs:718-730` already treats empty `peer_ids` as legitimate). Empty `managed_peer_ids` is legitimate **only on a single-node mesh**; a multi-node membership with empty `managed_peer_ids` is drift the orchestrator expectation check catches naturally (expected id not present → error).
- **Malformed**: snapshot CSV values are opaque strings today. `managed_peer_ids` entries must validate as node-id strings at the collector boundary; a collector that cannot parse an entry must surface it in the report as drift, never skip it. (Windows mechanics `:179-182` compare strings; add a format check at report build, not at compare.)
- **Stale**: unchanged — `--max-age-seconds` staleness bound already flows through `probe_expectations` (`validate_runtime.rs:65-76`), and heartbeat persistence is skipped while restricted/fail-closed (`daemon.rs:10326-10342`), so staleness remains a real signal.
- **Set by someone who should not**: the snapshot file is local privileged daemon state (existing threat model, unchanged). Expectations are orchestrator argv (`main.rs:1047`), derived from orchestrator-held `ctx.node_ids`, not from anything the report says. The report is read-only evidence; nothing downstream writes through it. No new trust boundary is introduced.
- **The vacuous-pass trap (the actual QH-81 lesson)**: a report whose `managed_peer_ids` field is *absent* (old-format snapshot that somehow loads, or a collector regression) must fail the stage, not pass vacuously. The orchestrator treats `Ok(passed=true)` with a report lacking `managed_peer_ids` on a multi-node context as a stage failure. This is the F2-class guard the reverted `d944c700` attempt lacked an execute-level test for.

## 5. What this does NOT solve

- It does **not** prove live handshake recency. `mesh_status_validation`'s live-handshake poll (`path_latest_live_handshake_unix`, `path_live_peer_count`) stays exactly as it is; until this fix lands it remains the only live peer-visibility proof, after the fix it additionally verifies membership. Different assertions, both kept.
- It does **not** fix the legacy focused-runner gap: `evaluate_linux_mesh_status_report` (`crates/rustynet-cli/src/vm_lab/mod.rs:23631-23656`) still accepts `overall_ok: true` with empty expectations, pinned by its own tests (`mod.rs:50377-50401`), and the macOS/Windows focused runners never check the field. Follow-up under QH-81, not in this design (OD3).
- It does **not** change the single-node semantics: one-node runs still pass vacuously with zero expectations. That is honest (there is no peer to expect), not permissive.

## 6. Test plan — each test names the mutation it catches

1. `resilience.rs` round-trip: snapshot with `advertised_route_cidrs=10.7.0.0/24` + `managed_peer_ids=node-b` survives write→load with both fields intact. *Catches: parser dropping the new required key (regression to tolerate-absent).*
2. `resilience.rs` negative: old-format file (`peer_ids=` only) fails load with `InvalidFormat`. *Catches: a dual-read compatibility fallback sneaking back in (CLAUDE.md §3 violation).*
3. `daemon.rs` persist test: seeded `advertised_routes={10.7.0.0/24}` + managed peers `[node-b]` → snapshot body contains `advertised_route_cidrs=10.7.0.0/24` and `managed_peer_ids=node-b`. *Catches: the exact QH-81 mutation — node ids/CIDRs swapped or the CIDRs landing back in a peer-named field.*
4. `daemon.rs` restore test: restore re-fills `advertised_routes` from `advertised_route_cidrs` only; `managed_peer_ids` does not leak into route state. *Catches: swap during restore (silent route-table corruption).*
5. Collector test (each platform): expected `[node-b]` vs `managed_peer_ids=[node-a]` → drift error string present; expected ⊆ managed → ok; report built from a snapshot missing `managed_peer_ids` → report flags the check unsatisfiable. *Catches: empty/absent-is-pass regression — the core vacuous defect.*
6. `validate_runtime.rs` execute-level regression: adapter double returns a `passed=true` MeshStatus report lacking `managed_peer_ids` on a 2-node context → stage verdict is **Failed**. *Catches: F2-class wiring vacuity — the class of bug that made the `d944c700` revert invisible to existing tests.*
7. `probe_expectations` unit: multi-node `ctx.node_ids` emits exactly one `--expected-peer-id` per non-self node; single-node emits none. *Catches: silent emission drop (the current defect at `validate_runtime.rs:65-76`).*

## 7. Effort

- **Mechanical (~2 days)**: field/key renames across `resilience.rs` + `daemon.rs` + three collectors; orchestrator emission; tests 1-4, 7; grep-sweep for every remaining consumer of the old names.
- **Judgement (~1-2 days)**: wiring `managed_peer_ids()` from `phase10.rs:8794` into `persist_state` (access path between the two structures is **UNVERIFIED** until attempted); absent-field semantics in collectors + test 5-6; the OD1 restore-posture decision and its verification. Total **3-4 days** plus the live-lab verification run that gates the ledger row.

## 8. Owner decisions (open; not invented here)

- **OD1 — old snapshot files after the rename.** (a) Hard fail: restore returns `InvalidFormat`, node starts in its existing restore-failure posture; operator re-advertises routes (repo-law clean, one-time cost per node). (b) Version marker + explicit migration step. **Recommend (a)** — (b) is a compat branch CLAUDE.md §3 forbids. Requires confirming the restore-failure posture is genuinely fail-closed (currently UNVERIFIED).
- **OD2 — source of `managed_peer_ids`.** `phase10.rs:8794` (the WireGuard peer table — same table the live-handshake poll reads, so membership and recency stay coherent) vs membership/gossip-derived (`gossip_runtime.rs:890`/`:431`). **Recommend phase10 peer table.**UNVERIFIED whether `persist_state` can reach it without refactor.
- **OD3 — legacy evaluator/focused-runner cleanup scope.** Fix `evaluate_linux_mesh_status_report` + mac/win focused runners in the same change (bigger blast radius, one coherent landing) or as a tracked follow-up. **Recommend follow-up** filed under QH-81 in `QualityHardeningTodo_2026-07-25.md`, so this fix lands small and reviewable.
