# Cross-OS ledger columns measure the wrong thing — plan — 2026-08-12

**Status: PLAN, pre-review.** Written against `HEAD = 56919423`, clean tree. Every number
below was produced by parsing the ledger with `csv.DictReader` or by reading the registry at
that commit.

## 0. The defect, quantified

Three `cross_os_*` columns are fed **only by Bootstrap-group distribution stages** — host→guest
SSH pushes of signed bundles. They report "we pushed a bundle" under names that promise a
dataplane or convergence property. The one column fed by a real reachability validator tells
the opposite story:

| column | lifetime | sole/primary feeder | what the feeder actually proves |
| --- | --- | --- | --- |
| `cross_os_direct_path` | **10 pass** | `distribute_traversal` (Bootstrap) — **only feeder** | a traversal bundle was copied to the guest |
| `cross_os_membership_convergence` | **10 pass** | `membership_init` + `distribute_membership` (Bootstrap) | membership was written to the guest |
| `cross_os_dns` | **10 pass** | `distribute_dns_zone` (Bootstrap) **plus** three real validators | mixed: a push can carry the column green |
| `cross_os_relay_path` | **3 pass** | `deploy_relay_service`, `relay_validation`, the lifecycle validators | the relay service started and bound ports |
| **`cross_os_peer_visibility`** | **0 pass / 9 fail** | `traffic_test_matrix`, `live_mixed_topology`, the mesh-join validators | **actual guest-to-guest reachability** |

So the matrix simultaneously asserts `cross_os_direct_path = pass` ten times and
`cross_os_peer_visibility = fail` nine times — for the same fleet. A reader concludes cross-OS
direct paths work. **They have never worked.**

**Why the pushes pass through a total severance:** the orchestrator host owns *both* vmnet
bridges, so a host→guest SSH push succeeds regardless of whether the guests can reach each
other. `distribute_traversal` therefore cannot fail for the reason its column name implies.

`cross_os_relay_path` is the same shape one step removed: lifecycle stages prove the service
runs, while relay frame forwarding (HP-3) has **never been proven on any OS or engine**.

## 1. This is the third instance of one class

- **QH-07** — `traffic_test_matrix` carried a `logical` alias onto `two_hop`, so 35 rows read
  `two_hop=pass` for a stage with 0 lifetime passes. Fixed by removing the alias at source;
  forward-only.
- **QH-37** — a merged column let one `pass` outrank nine `skip`s. Fixed by precedence.
- **This** — a column's *name* promises a property its *feeder* does not measure.

The first two were fixed at the registry, and that is the precedent to follow: **change what
feeds the column, not how the column is rendered.**

**Nothing guards this today.** `every_registry_stage_column_reference_exists_in_the_csv_schema`
checks a column *exists*; `cross_os_family_stages_are_tiered_t3_cross_os` checks *tiering*.
Neither asks whether a feeder measures what its column claims.

## 2. The change

### C1 — stop distribution stages feeding reachability columns

Remove `cross_os` from the four Bootstrap-group distribution specs:
`distribute_traversal`, `distribute_dns_zone`, `membership_init`, `distribute_membership`.

`cross_os_bootstrap` is **deliberately left alone**: its six feeders are all Pre/Bootstrap
setup stages and its name says exactly that. It is the one honest aggregate here.

### C2 — accept that two columns become unfed, and say so

After C1, `cross_os_direct_path` has **no feeder at all** and
`cross_os_membership_convergence` has none either. That is the correct state: nothing in the
current stage set measures either property.

**Do not delete the columns.** They stay in the schema reading `not_run`, which is now the
truth — "nothing measured this" — and they mark where a real validator is owed. Deleting them
would erase the gap rather than expose it. Record in the register which validator each is
waiting for.

### C3 — a structural guard so this cannot regress

A test asserting: **no stage in `StageGroup::Pre` or `StageGroup::Bootstrap` may declare a
`cross_os` mapping, except the `cross_os_bootstrap` column itself.** That is the invariant the
three defects above all violate in different ways, and it is checkable from the registry with
no runtime data.

### C4 — `cross_os_relay_path` is a DECISION, not obviously a fix

Its feeders prove lifecycle, not forwarding. Renaming it (`..._service_lifecycle`) or
unfeeding it are both defensible, and both are schema-visible. **This plan does not take that
decision** — it is a judgement about what the column is *for*, and the evidence (HP-3 never
proven) argues the name oversells while the lifecycle signal is still genuinely useful.
Flagged for the operator.

## 3. Blast radius

- **Forward-only**, exactly as QH-07 and QH-37 were. The 10 historical `pass` values in each
  affected column stay wrong and must not be read as evidence. Record that boundary.
- **Future runs report `not_run`** on those columns instead of `pass`. That is a *reduction* in
  apparent coverage and an *increase* in accuracy. Say so plainly rather than letting it look
  like a regression.
- **No stage stops running.** The distribution stages keep their own `logical` columns; only
  the cross-OS roll-up mapping is removed.
- **Nothing gates on these columns today** — no CI step reads the ledger — so the change
  cannot break a gate. It changes what a human or tool concludes.

## 4. Tests, each with the mutation that proves it discriminates

1. No Pre/Bootstrap stage declares a non-`cross_os_bootstrap` mapping. *Mutation:* restore
   `cross_os: Some("cross_os_direct_path")` on `distribute_traversal` → fails.
2. `cross_os_bootstrap` still has its six Pre/Bootstrap feeders. *Mutation:* also strip them →
   fails. Pins the deliberate exception so a blunter rule cannot be substituted.
3. `cross_os_direct_path` and `cross_os_membership_convergence` remain in the schema with zero
   feeders. *Mutation:* delete either column → the existing schema test fails; *mutation:*
   re-feed either → test 1 fails.
4. `cross_os_peer_visibility` keeps its reachability feeders. *Mutation:* remove
   `traffic_test_matrix`'s mapping → fails. Guards the one column that works.

## 5. Definition of done

All §7 gates green; every test mutation-proven; a register entry recording the forward-only
boundary and which validator each unfed column awaits; and §0's table reproducible with
`csv.DictReader`.
