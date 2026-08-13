# `mesh_status_validation` passes vacuously — plan — 2026-08-13

**Status: PLAN, unreviewed.** Every claim is a code citation read at `548c5d13`.

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
