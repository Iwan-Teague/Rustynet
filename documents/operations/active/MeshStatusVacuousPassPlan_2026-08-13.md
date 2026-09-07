# `mesh_status_validation` passes vacuously — plan — 2026-08-13

> **REVISION 2 — C1 IS UNIMPLEMENTABLE AS WRITTEN. Found by answering this plan's own §5 Q1
> before touching code, which is the only reason it was caught.**
>
> The snapshot field named `peer_ids` does not contain peers. It is a serialization alias for
> advertised route CIDRs:
>
> ```rust
> // daemon.rs:9129  (write)
> peer_ids: self.advertised_routes.iter().cloned().collect::<Vec<_>>(),
> // daemon.rs:9196  (load, round-trips straight back)
> self.advertised_routes = snapshot.peer_ids.into_iter().collect::<BTreeSet<_>>();
> // daemon.rs:3750  advertised_routes: BTreeSet<String>, populated by `advertised_routes.insert(cidr)` (:8405, :8438)
> ```
>
> The whole snapshot is `timestamp_unix`, `peer_ids`(=routes), `selected_exit_node`,
> `lan_access_enabled` (`resilience.rs:38`) — it carries **no peer identity information at all**.
>
> So passing `--expected-peer-id <node_id>` compares a node id against a CIDR and can never
> match. C1 would have replaced a vacuous pass with a **permanent false failure** on every node —
> strictly worse, and it would have been diagnosed as a real outage.
>
> `--max-age-seconds` is unaffected: the timestamp is real. That half of C1 stands.
>
> **This makes the defect deeper than "the orchestrator forgot a flag".** The check is
> structurally incapable of validating peers, because the data it inspects is not peers. The
> daemon's `--expected-peer-id` flag is itself latently wrong for the same reason.

**Status: PLAN (REVISION 2). C1 blocked; C2 stands.** Every claim is a code citation read at `548c5d13`.

## 0. The defect

`mesh_status_validation` reports **pass** whenever the state snapshot merely exists, parses and
passes integrity. It asserts nothing about peers and nothing about freshness.

The evaluator takes both as parameters and skips both when they are empty
(`rustynetd/src/windows_mesh_status.rs:146-188`):

```rust
if let Some(max_age) = max_age_seconds {        // None  -> staleness never checked
    if *age_seconds > max_age { ... }
}
for expected in expected_peer_ids {             // []    -> peer presence never checked
    if !peer_ids.iter().any(|p| p == expected) { ... }
}
// overall_ok = reasons.is_empty()
```

The daemon **does** accept both (`rustynetd/src/main.rs:927-940`:
`--expected-peer-id`, `--max-age-seconds`). The orchestrator simply never passes them:

```rust
// vm_lab/orchestrator/role_validation/mesh_status.rs:31, :45, :60
let argv = [daemon_path, SUBCOMMAND];   // no arguments, all three platforms
```

So `expected_peer_ids = []` and `max_age_seconds = None` on every invocation, on Linux, macOS
and Windows alike.

**This is the exact hazard the repo already knows about** — `identity_challenge.rs:5`/`:15` call
it "the historical MeshStatus false-green". It was fixed for identity and left unfixed here.

**It is also a self-contradicting doc comment.** `mesh_status.rs:5-8` claims the validator
"fails closed on schema mismatch or `overall_ok=false` — so a broken or **vacuous** check fails
the stage rather than silently passing". That protects against a vacuous *report*; it does not
protect against a vacuous *invocation*, which is what actually happens.

## 1. Why it matters now

`mesh_status_validation` passed on `macos-utm-1` in four consecutive runs while that node
reached **no mesh peer at all** (100% loss both directions, `traffic_test_matrix` red). A green
mesh-status on a node with no working dataplane is precisely the false coverage this project
keeps getting burned by, and it was cited — by me — as evidence that "the macOS control plane is
healthy". That citation was wrong, and the fix is what makes it checkable.

## 2. The change

### C1 — pass the expected peers and a max age

The orchestrator knows the topology. For each validated node, pass every **other** assigned
node's `node_id` as `--expected-peer-id`, and pass `--max-age-seconds`.

All three platform functions take the same shape, so the change is one signature plus three
argv constructions.

### C2 — choose the max-age honestly

The snapshot is written during the run, so the bound must cover a full run's duration without
being meaningless. Proposed: **900s**, argued rather than picked — the longest observed run is
13m53s (833s) end-to-end, and mesh-status runs well before the end, so 900s cannot mask a
snapshot that stopped updating at the start of the run while still tolerating the slowest
observed lab. Review should challenge this number; a value that can never fire is a second
vacuous check.

### C3 — do not paper over the consequence

This will likely turn `mesh_status_validation` **red on macOS** if its snapshot lacks the peer
ids. **That is the correct outcome and must not be softened.** If it goes red, the stage is
finally reporting the truth that `traffic_test_matrix` has been reporting all along.

Note what the fixed check does and does not prove: peer **presence in the snapshot** is
membership convergence, not reachability. It is a real strengthening — file-loads → file loads
AND is fresh AND names the peers it should — but it is not a dataplane proof and must not be
cited as one.

## 3. Blast radius

- Three platforms, one call site each. No wire-format or schema change; the daemon side already
  parses both flags.
- Every currently-green `mesh_status_validation` may flip. Linux nodes that genuinely converged
  should stay green; a node that did not will go red. Both are improvements.
- The ledger columns `*_stage_mesh_status` change meaning from "snapshot loads" to "snapshot
  loads, is fresh, and contains the expected peers". **Historical rows are not comparable** and
  that boundary must be recorded — the same forward-only caution as QH-07 and QH-37.

## 4. Tests, each with the mutation that proves it discriminates

1. Evaluator flags a missing expected peer. *Mutation:* pass `[]` → no reason produced → fails.
   (Pins that the argument is load-bearing, which is the whole defect.)
2. Evaluator flags a stale snapshot. *Mutation:* pass `None` for max age → no reason → fails.
3. The orchestrator's argv **contains** `--expected-peer-id` for each peer and
   `--max-age-seconds`. *Mutation:* revert to `[daemon_path, SUBCOMMAND]` → fails. This is the
   test that would have caught the live defect, and none existed.
4. A node with exactly one peer expects exactly that peer, not itself. *Mutation:* include self
   in the expected list → fails (self is not a peer in the snapshot).

## 5. Open questions for review

1. **Is `node_id` the right identifier?** The snapshot's `peer_ids` must use the same namespace
   as the orchestrator's assignments. If the snapshot carries WireGuard keys or overlay
   addresses rather than node ids, C1 produces a validator that always fails — the mirror
   defect. Settle from the snapshot writer, not from the field name.
2. **Should every node expect every other node?** In a topology with a relay or an exit, is
   full-mesh membership the correct expectation, or do some roles legitimately not carry all
   peers?
3. Is 900s defensible, or should the bound derive from the run's own start time?
4. Should Windows change in the same commit given it has never run this stage live, or is
   changing an unexercised platform a needless risk?
5. Does any other validator have the same shape — parameters accepted by the daemon but never
   passed by the orchestrator? `identity_challenge` was fixed; what else was not?

## 6. Definition of done

The argv carries both flags on all three platforms; every test above is mutation-proven; a live
run shows the stage's verdict changing where it should; the ledger-semantics boundary is
recorded; and the misleading doc comment at `mesh_status.rs:5-8` is corrected in the same change.

## Addendum 2026-09-07 — QH-70: live-handshake evidence (owner decision 5, stage-side)

<!-- Drafted 2026-09-07 by a glm-5.3-flash grounded read-only agent at the owner's request (owner decision 5, QH-70); reviewed and placed by the managing Claude session. Status: PLAN — implementation tracked in OwnerDecisions_2026-09-07.md. Line references are against main at 2a5c4e1d unless stated. -->


## Goal
`mesh_status_validation` must fail unless the node presents **live dataplane evidence**: ≥1 live peer and a fresh latest-handshake whenever the run topology expects peers. Snapshot-loads-and-is-fresh stays necessary but is no longer sufficient.

## Existing state
- Prior fix (Revision 2, C2) landed: all three `validate_*_mesh_status` dispatch `--max-age-seconds 180` (`role_validation/mesh_status.rs:15`, `:61-66`, `:99-103`, `:135-139`); macOS adds `--expected-node-id` (`:84-88`). That still proves only snapshot convergence, not dataplane — exactly the gap that plan §2/C3 flags ("membership convergence, not reachability").
- The stage loops every assigned alias and calls `adapter.run_role_validator(RoleValidatorKind::MeshStatus, expected_node_id, None)` (`stage/mesh_status_validation.rs:55-71`); dispatch per platform at `adapter/node_adapter.rs:614-629`; trait signature `node_adapter.rs:272-279`.
- The daemon's IPC `status` line already carries the needed fields — `path_programmed_peer_count`, `path_live_peer_count`, `path_latest_live_handshake_unix`, `relay_session_*` (`rustynetd/src/daemon.rs:9259`; `latest_live_handshake_unix` is max-over-peers, `daemon.rs:8431-8500`).
- Cross-OS precedent for querying status live: Linux `query_live_identity` runs `rustynet status` with `RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock` (`adapter/linux_traffic.rs:394-399`); Windows via trust-CLI `status` verb (`windows_traffic.rs:148-165`); macOS queries `rustynet status` only (`macos_traffic.rs:345`).
- Poll-deadline + pure-evaluator + `MockShellHost` template already exists: `role_validation/gossip_convergence.rs:37-40` (150s/10s), `:63-67` (status argv), `:79-96` (`splitn(2,'=')` token/field/count helpers), `:98+` (fail-closed evaluator).
- Handshakes complete asynchronously post-enforce (`stage/traffic_test_matrix.rs:90-96`), so a first-poll failure would be flaky.
- Stage order: MeshStatusValidation (plan.rs:1012) runs **before** DeployRelayService/RelayValidation/TrafficTestMatrix (plan.rs:1016-1018), so relay sessions may legitimately be absent at this point.

## Design
1. **New pure evaluator** — `role_validation/mesh_status.rs`:
```rust
/// Live-handshake evidence window. Same 180s basis as SNAPSHOT_MAX_AGE_SECONDS:
/// a WireGuard handshake rekeys ≤~180s under traffic; if the daemon keeps none
/// alive inside this window the dataplane is idle-dead, which is the false-green
/// QH-70 exists to catch. Future-dated handshake_unix fails (no slack).
pub(crate) const MAX_HANDSHAKE_AGE_SECONDS: u64 = 180;

pub fn evaluate_live_handshake_status(
    alias: &str, stdout: &str, expected_live_peers: u32, now_unix: u64,
) -> Result<(), String>
```
Parse with the `splitn(2,'=')` helpers (copy the three small fns from `gossip_convergence.rs:79-96`, or hoist them into `role_validation/mod.rs` and reuse). Fail closed when:
- any required field missing/unparseable: `path_live_peer_count`, `path_programmed_peer_count`, `path_latest_live_handshake_unix`;
- `expected_live_peers > 0` and `path_live_peer_count == 0` or `path_programmed_peer_count == 0` (programmed-but-not-live = dataplane applied, handshake never proven; mirrors `linux_traffic.rs:591-603`);
- `now_unix.saturating_sub(handshake_unix) > MAX_HANDSHAKE_AGE_SECONDS` or `handshake_unix > now_unix`.
`relay_session_state`/`relay_session_established_peers` are parsed and echoed into the failure/evidence string but **never gate** here — relay deploy is two stages later (plan.rs:1016). `expected_live_peers == 0` skips the peer/handshake clauses (single-node run).
2. **Adapter plumbing** — add to `NodeAdapter` (default = `Err(AdapterError::UnsupportedPlatform)`, the `probe_membership_owner_signing_key_present` pattern at `node_adapter.rs:216-229`):
```rust
fn collect_daemon_status(&self) -> Result<String, AdapterError> { ... }
```
Implemented per platform from the three existing `query_live_identity` status queries (`linux_traffic.rs:394`, `macos_traffic.rs:345`, `windows_traffic.rs:148`), returning full status text instead of extracting `node_id`.
3. **Stage wiring** — `stage/mesh_status_validation.rs`, inside the per-alias loop after `run_role_validator` succeeds:
```rust
let expected_live_peers = (ctx.assignments.len().saturating_sub(1)) as u32;
let deadline = Instant::now() + LIVE_HANDSHAKE_DEADLINE; // 120s, poll 10s — gossip_convergence.rs:37-38 precedent
loop { match adapter.collect_daemon_status() { ... evaluate_live_handshake_status(alias, &s, expected_live_peers, now_unix()) ... } }
```
Peers expected = **every other assigned node** (`assignments.len() - 1`): traffic_test_matrix pings all pairs (`traffic_test_matrix.rs:105-110`), so full-mesh liveness is the run's own contract; zero live peers on a multi-node run is the QH-70 defect. Any dispatch/eval error after the deadline → `failures` (existing fail-closed path, `mesh_status_validation.rs:70-72`).
4. Correct the doc comment (`mesh_status.rs:5-8` / stage doc `:11-19`): "pass" now means snapshot-valid **and** live-handshake-proven; ledger semantics change (forward-only, as plan §3 warns).

## Security analysis
Fail-closed preserved: missing/unparseable status → error → stage failure; empty output denied (gossip evaluator precedent); no new trust boundary — reads the same local IPC surface the §4.7 challenge already trusts; no secrets in output (status line carries public-key material only, `daemon.rs:9259` `local_wg_public_key`). Risk: over-strict window reds healthy-but-idle nodes — mitigated by the poll deadline, and it is the safe direction. A future-dated timestamp check must use `saturating_sub` and explicit `>` comparison, not `abs()`.

## Tests (stub `MockShellHost`, pattern `mesh_status.rs:112-160` / `gossip_convergence.rs:169+`)
1. live=0, expected=1 → fail; live=1, fresh handshake → pass.
2. Stale handshake (now−ts = 181s) → fail; boundary 180 → pass.
3. Future-dated `path_latest_live_handshake_unix` → fail.
4. Missing any of the three fields / empty output / `garbage` → fail (mutation: delete a field).
5. expected=0 (single-node) with live=0 → pass (mutation: drop the expectation → fail).
6. Dispatch mutation: mock programmed only for status argv + socket env; dropping the status query breaks the test (the `every_platform_dispatch_passes_the_freshness_bound` pattern, `mesh_status.rs:243+`).
7. Adapter: `collect_daemon_status` default impl returns `UnsupportedPlatform` (never a silent "no peers").
**Live proof:** next full `--node` Live run's `mesh_status_validation` stage — it must now agree with `traffic_test_matrix` (latest comparable run `3aedcfff`, 2026-09-05, failed exactly on `traffic_test_matrix`); a red mesh_status on that same node class is the defect closing.

## Effort
~1 day: evaluator + tests (half day), three adapter impls + stage wiring + doc comments (half day), one live run to prove.

## Open questions
1. Is 180s the right handshake window on an idle-but-healthy node — does the daemon send persistent keepalives at this plan point (unverified)? If not, only the post-`traffic_test_matrix` window would be safe, which conflicts with stage order; measure from the next run before committing the constant.
2. Should macOS/Windows status implementations also carry `sudo`/env differences (Linux needs `RUSTYNET_DAEMON_SOCKET`; macOS socket path unverified here)?
3. Should the relay-session clauses gate a *later* stage (post-RelayValidation) instead — separate increment?
4. Do role-switch/fast-run workflows that legitimately show `path_live_peer_count=0` (`mod.rs:14885-14890`) ever reach this stage, or only the bash-era suite?


## Implementation log
- 2026-09-07 (QH-70 addendum, delegated edit branch `ai-edit/edit-1788775586214-74221-0`): step 1 — add `MAX_HANDSHAKE_AGE_SECONDS=180` + pure `evaluate_live_handshake_status` (fail-closed on missing/unparseable fields, zero live/programmed peers when expected, stale or future-dated handshake; relay fields echoed, never gating) to `role_validation/mesh_status.rs` with the addendum's evaluator tests. Deviation logged here per the plan's contract: the helpers are COPIED from `gossip_convergence.rs:79-96` (the addendum allows copy-or-hoist; copy avoids touching a second module's private surface).
- 2026-09-07: step 2 — `NodeAdapter::collect_daemon_status` default `Err(UnsupportedPlatform)`; per-platform impls in the three adapters delegating to new `collect_daemon_status(conn)` fns in `linux_traffic.rs`/`macos_traffic.rs`/`windows_traffic.rs`, each reusing the EXACT proven `query_live_identity` status command (sudo + socket env + `rustynet status`; Windows trust-CLI `status` verb script). Deviation logged: the Linux/macOS status query goes through `ssh::run_remote` (NodeConnection) like `query_live_identity` — NOT the `RemoteShellHost` seam — because the proven live queries carry `sudo -n env`, which the seam's env-param argv does not express; the addendum's MockShellHost "dispatch mutation" test therefore pins the command STRING builders (socket env + `status` verb present) instead of a programmed argv, which fails identically if the status query or socket env is dropped.
- 2026-09-07: step 3 — stage wiring in `stage/mesh_status_validation.rs`: after the existing validator passes per node, poll `collect_daemon_status` (120 s deadline, 10 s interval, `gossip_convergence` precedent) and require `evaluate_live_handshake_status` to pass with `expected_live_peers = assignments.len()-1` (full mesh is the run's own contract — `traffic_test_matrix` pings all pairs). Any poll/dispatch/eval error past the deadline joins the existing fail-closed `failures` path. Stage + module doc comments corrected: "pass" now means snapshot-valid AND live-handshake-proven; ledger semantics change is forward-only.
- 2026-09-07: step 4 — gates: `cargo fmt --all -- --check`; `cargo clippy -p rustynet-cli --all-targets --all-features -- -D warnings`; `cargo test -p rustynet-cli --all-targets --all-features` (mesh_status filter first — green, then full crate).
- 2026-09-07: gates result — fmt check PASS (also normalized two pre-existing unformatted test blocks in `linux_traffic.rs`/`macos_traffic.rs`); clippy `-p rustynet-cli --all-targets --all-features -- -D warnings` PASS; `cargo test -p rustynet-cli --all-targets --all-features` PASS (8412 passed, 0 failed). One gate iteration: the new `run_remote` call sites tripped the `raw_sink_call_site_count_must_only_go_down` tripwire (130→131); fixed by passing the compile-time-constant command through the established seam-lowered shape (`let command = DAEMON_STATUS_COMMAND.to_owned(); run_remote(conn, command.as_str(), …)`), baseline left untouched — no interpolation exists at either site.
