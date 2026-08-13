# `live_managed_dns_validation` breaks on a second client — plan — 2026-08-13

**Status: PLAN, unreviewed.** Diagnosed from the first run in which this stage ever executed.

## 0. The defect

The stage failed in `linuxonly-20260813m` with:

```
assignment bundle for debian-headless-2-bootstrap
  references unmanaged peer rocky-utm-1-bootstrap
```

**The validator is right to refuse.** `build_authorized_allow_spec`
(`bin/live_linux_managed_dns_test.rs:1550-1560`) walks each node's assignment scope and requires
every referenced peer to be present in `host_by_node`, failing closed otherwise. It cannot build
an allow-spec naming a host it was never given.

The defect is in the caller. `managed_peer_args`
(`stage/live_managed_dns_validation.rs:174-180`) builds the `--managed-peer` list with:

```rust
if assignment.role.as_str() == "exit" || assignment.role.as_str() == "client" {
    continue;
}
```

It skips by **role**, because the signer and the client are passed separately as
`--signer-*` / `--client-*` (`:53-54`, from `signer_params.alias` / `client_params.alias`).
That is correct for exactly one client. This topology has two — `debian-headless-4` and
`rocky-utm-1` are both `client` — so the second is silently dropped, while
`distribute_assignments` still builds a **full-mesh** ALLOW_SPEC that references it.

So the bundle names a node the validator was never told about, and it fails closed.

## 1. Why it only appeared now

This stage had never executed. It sits ~10 deep in a cascade behind `traffic_test_matrix`, which
failed in five consecutive runs because `macos-utm-1` cannot reach the other guests. Running an
all-Linux topology cleared the cascade and this stage ran for the first time, immediately
exposing an assumption that had never been tested: **exactly one client**.

That is the expected shape of new frontier — the stage is not newly broken, it was newly
*reached*.

## 2. The change

Exclude the two nodes that are already passed separately, **by alias**, rather than excluding
two whole roles:

```rust
fn managed_peer_args(ctx: &OrchestrationContext, signer_alias: &str, client_alias: &str) -> Vec<String> {
    for assignment in &ctx.assignments {
        if assignment.alias == signer_alias || assignment.alias == client_alias {
            continue;
        }
        ...
```

Every other assigned node becomes a managed peer regardless of role, which matches what the
full-mesh assignment bundle actually contains.

## 3. Blast radius

- Three-node topologies are unaffected: with one client, alias-exclusion and role-exclusion
  select the same set. That is also why no existing test caught this.
- Four-plus-node topologies gain the previously-dropped peers. The validator will now re-push
  bundles to them, which is the point.
- No wire format, no bundle change, no daemon change.
- Risk: a node that cannot accept the Linux-only bundle re-push (a macOS or Windows client) would
  now be included where it previously was not. `platform_by_node` already carries per-peer
  platform and the validator already decides re-push eligibility from it — verify that holds
  rather than assuming it (§5 Q2).

## 4. Tests, each with the mutation that proves it discriminates

1. With two clients, `managed_peer_args` includes the non-selected client. *Mutation:* restore
   the role filter → the second client is dropped → fails. This is the exact live defect.
2. With one client, the selected client is NOT included (no duplicate with `--client-*`).
   *Mutation:* drop the alias exclusion → the client appears twice → fails.
3. The signer is never included as a managed peer. *Mutation:* drop the signer exclusion → fails.
4. A non-client, non-exit role (relay) is still included. *Mutation:* exclude by role again →
   the relay is dropped → fails. Guards against "fixing" this by widening the role list.

## 5. Open questions for review

1. Is alias the right identity to exclude on, or should it be `node_id`? The map is keyed by
   `node_id` downstream; if two aliases can share a node_id, alias-exclusion is wrong.
2. Does the validator handle a **macOS/Windows** managed peer correctly once included? The
   comment at `:176-179` says the Linux-only re-push is gated on platform — confirm the gate
   exists and is exercised, or this fix turns a silent drop into a loud failure on mixed
   topologies.
3. Should the validator ALSO fail loudly when a node in `ctx.assignments` is missing from the
   managed-peer list, rather than depending on the bundle to reference it? A positive check
   would catch the next variant of this instead of relying on the allow-spec walk.
4. Are there sibling stages with the same one-client assumption? `live_two_hop_validation` and
   `live_lan_toggle_validation` take similar signer/client params — check them.

## 6. Definition of done

The stage passes in the 4-node all-Linux topology; every test above is mutation-proven; §7 gates
pass; and if Q4 finds siblings, they are filed rather than silently left.
