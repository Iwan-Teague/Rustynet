# Fleet evidence collection and host identity

**Status:** OPEN — design only, nothing implemented. Raised 2026-07-28.
**Revision 2**, after an adversarial review BLOCKED revision 1 with two critical
defects. What changed is recorded at the end, because the errors are instructive
and one of them would have destroyed evidence.

Tracks task-list items #28–#31.

## The problem

A live-lab run on `ubuntu-kvm-1` writes its evidence into that box's own
checkout and it does not come home. On 2026-07-28 the box held 201 unmerged
lines from two runs on 27 Jul (`livelab-1785146925-9cdd660f1ecd`,
`livelab-1785164429-0bc7f68ccb52`). Those rows were preserved as a patch and
then DISCARDED from the box during the sync — they now exist only in
`scratchpad/SAFETY-BACKUP-f9388393/ubuntu-box-lab-artifacts.patch`, so the
motivating example is no longer reproducible in-tree. The problem class stands
regardless.

A remote run also leaves ~5.3 MB per cell in its report dir: per-stage logs,
diagnostics archives, `report_state.json`. Diagnosing a remote failure means SSH.

## 0. First: does a host column answer the question at all?

Revision 1 opened with *"passed **where**?"* and proposed a driver-host id. The
review pointed out that a driver-host id does not answer that question. The same
guest can be driven from two different hosts, yielding two differently-attributed
rows for one machine's outcome — and **`node_id` already exists** in
`stage_results.csv` (verified: it is column 8).

So the two questions must be separated before anything is built:

- *"Which guest produced this result?"* — already answered by `node_id`. No work
  needed.
- *"Which machine drove the run?"* — NOT currently recorded, and genuinely
  unanswerable today. It matters for attributing environment-specific failures
  (a flake that only appears on one driver, a stale checkout on one box, a
  toolchain difference).

**Only the second justifies new work**, and it is a weaker motivation than
revision 1 implied. Decide whether it is worth the schema cost in §2 before
proceeding. This plan does NOT assume it is.

## 1. Host identity

### Rejecting the MAC — corrected

Revision 1 claimed this Mac has no stable MAC, citing `ifconfig en0` →
`12:fd:56:25:25:e8` (locally-administered bit set) and asserting macOS rotates
it. **That was marked "verified" and was wrong.** `en0` is Wi-Fi, and that value
is the private *association* address, which does rotate — but the burned-in
hardware MAC is one command away and is stable:

    networksetup -getmacaddress en0   ->  5c:9b:a6:65:33:98   (Apple OUI)

The verification stopped at the first command that appeared to confirm the
hypothesis.

**MAC-hashing is still rejected, on the entropy ground alone, which does hold.**
A MAC is 48 bits with a publicly-known 24-bit OUI prefix, leaving ~16.7 million
candidates — enumerable in seconds. Hashing a low-entropy identifier does not
conceal it. That argument is sufficient by itself.

### The anchors, and their real weakness

| host | anchor | verified value |
|---|---|---|
| this Mac | `IOPlatformUUID` | `ED554A6F…` |
| ubuntu-kvm-1 | `/etc/machine-id` | `ff1a76c3…` (matches `/var/lib/dbus/machine-id`) |

Revision 1 checked **presence**, which is not the property required.
`/etc/machine-id` is generated at first boot and **baked into any image cloned
afterwards**. The fleet this plan exists for is cloned lab guests, so two guests
from one image would collide — the identical failure revision 1 accused the MAC
of. `IOPlatformUUID` is more durable but its survival across a wiped reinstall
or logic-board service is untested.

**Required before adoption:** clone a lab guest and confirm whether the two
report the same `machine-id`. If they do, the anchor needs a first-run
regeneration step (`systemd-firstboot --setup-machine-id`, or generate-and-store
our own id at provision time) — which is arguably the better design anyway, since
it makes the identity ours rather than borrowed.

### Derivation — simplified

Revision 1 proposed `HMAC-SHA256(salt, anchor)` and simultaneously stated the
salt would be public. Those cannot both hold: with a public salt, confirming a
guessed anchor costs one HMAC evaluation, exactly as with a bare hash. Against a
128-bit non-enumerable anchor the two are equivalent in every property that
matters here, so the HMAC bought **nothing** and read as security.

Use a plain hash with an explicit domain-separation prefix, and say what it does:

    host_id = SHA256("rustynet-host-id-v1:" || anchor)[0..16]   # 128 bits, hex

- The prefix is domain separation, not secrecy. It stops the same anchor
  producing a colliding id in some other context.
- The raw anchor never appears in a committed artifact.
- Truncation is specified: **128 bits**. Left unspecified in revision 1; at 128
  bits, birthday collision across any plausible fleet is negligible.
- If the id ever needs to be genuinely unguessable, that requires a real secret
  and the loss of third-party reproducibility. Not proposed here.

### Verifier

`verify_host_id(id) -> bool` recomputes from the LOCAL anchor and reports whether
`id` belongs to this machine.

Stated limit: this answers *"am I this host"*, not *"was this row written by that
host"*. A row can carry any id and nothing contradicts it. Row provenance needs
signing and is out of scope.

## 2. Ledger schema — three different files, three different problems

Revision 1 listed the three ledgers as one bullet. They are structurally
different and behave OPPOSITELY under a schema change. All figures verified
2026-07-28.

### `live_lab_node_stage_results.csv` — 12,699 rows, blocked

`upsert_node_stage_csv` (`live_lab_run_matrix.rs:862-867`) requires **exact**
header equality:

```rust
if header != NODE_STAGE_COLUMNS.join(",") {
    return Err(format!("node-stage matrix schema mismatch ({}); expected exact normalized schema", ...
```

There is **no upgrade path**. Adding `host_id` to `NODE_STAGE_COLUMNS` makes
every write against the shipped 12,699-row ledger fail immediately.

**A migration must be written first, or the column cannot be added at all.**
Append at the END, and the migration must rewrite the existing file's header and
backfill a sentinel (e.g. `unknown`) for historical rows — those runs genuinely
have no recorded host and must not be attributed to one.

### `live_lab_node_run_matrix.csv` — 94 rows × 266 columns, already handled

Wide format, one row per run. `ensure_matrix_schema` (`:922`) appends missing
columns and rewrites the header, so this file already tolerates the change.

### `live_lab_stage_triage.jsonl` — 51 entries, schemaless

JSON objects keyed by `stub_id`. A new field is additive and needs no migration.

### The positional-read hazard — corrected

Revision 1 claimed `run_matrix.rs` and the lab-monitor read these by positional
index. **The lab-monitor does not** — it resolves every column by name
(`run_matrix.rs:172`, `:458-460`, `:506`, `:693`, `:867`). The single genuine
positional reader is the file revision 1 cited as *precedent*:
`vm_lab/run_history.rs:20-22` (`TOPOLOGY_COLUMN = 11`, `OVERALL_RESULT_COLUMN = 12`,
`FIRST_FAILED_STAGE_COLUMN = 13`), already guarded by `validate_matrix_header`.
Appending at the end is safe for it.

So the warning pointed at a file that was fine and was silent about the file
that actually blocks the work.

## 3. Merge keys — one rule per ledger, not one rule

Revision 1 proposed merging on `(run_id, stage)` for all three. Verified against
the real data, that key would have **dropped 8,665 of 12,699 rows** in
`stage_results.csv`, because rows are per-node: only 4,034 distinct
`(run_id, stage)` pairs exist. It would have silently destroyed most of the
evidence while claiming to protect the oracle from duplication.

| ledger | correct key | verified |
|---|---|---|
| `stage_results.csv` | `(run_id, node_id, stage)` | 12,699 distinct / 12,699 rows — exact |
| `run_matrix.csv` | `run_id` | 94 distinct / 94 rows; **no `stage` column exists** |
| `stage_triage.jsonl` | `stub_id` (= `run_id::stage`) | already implemented |

Note the repo ALREADY implements an idempotency key for the matrix —
`(run_id, report_dir)` at `live_lab_run_matrix.rs:878-881`. Reuse it rather than
inventing a parallel scheme.

## 4. Collection — fetch and merge

The box keeps writing locally; on completion the orchestrator pulls that run's
rows and merges them under the existing lock. Not live remote-append: the box
stays robust to the SSH link dropping (the whole point of
`launch_live_lab_on_host`), and concurrent writers cannot interleave rows.

Default ON, explicit opt-out flag.

### Locking — partially present

`acquire_matrix_append_lock` (`live_lab_run_matrix.rs:855`, implemented
`:2198-2260`) is real: unix `flock(LOCK_EX)`, persistent lock file, and it
documents why unlinking on unix would let two acquirers flock distinct inodes.
Revision 1's characterisation was accurate here.

**But it covers the matrix only.** `live_lab_stage_triage.rs`'s `append_stub`
has no lock: it reads the ledger to check `stub_id`, then opens with
`append(true)` — a TOCTOU window where two concurrent appends both observe
absence and both write. The triage ledger was revision 1's **#1 fetch priority**,
so this must be fixed or the merge declared single-writer.

### Partial runs

Revision 1 said "merge on completion", which never fires for a box that dies
mid-run — precisely the scenario that motivates the plan. Needs a reaper: fetch
evidence for a run whose pidfile is dead but whose rows were never collected.

## 5. What else comes home

1. **Triage JSONL** — carries attempted remediation, unreconstructable later.
2. **Failed stages' logs** — where diagnosis happens.
3. **A small tail of PASSING stage logs** (last N KB). Revision 1 said "nobody
   reads the logs of stages that passed"; this repo's own history refutes that —
   `live_lab_run_matrix.rs:443-453` documents 35 `linux_stage_two_hop=pass` rows
   that were contaminated and had to be re-examined against per-stage evidence.
   Under fetch-on-failure-only, that evidence sits on a box that may be reimaged.
4. **Diagnostics archives** — reliably collectable since the locked-log fix.
5. **`report_state.json` + stage manifest** — small, always fetch.

Not the full 5.3 MB on a passing run.

## 6. Open issues revision 1 missed entirely

- **Binary version skew.** Given §2's exact-header equality, a remote running an
  older binary emits 17-column rows into an 18-column ledger and fails closed.
  This is the dominant operational risk of the whole plan.
- **Git merge conflicts.** All three ledgers are git-tracked. Two machines
  committing appends conflict on essentially every run. Decide: `.gitattributes`
  union merge, or the remote never commits ledgers and only the orchestrator does.
- **Growth.** Appending to `stage_results` is a full read-modify-rewrite of
  6.4 MB under lock on every finalize. Fleet-multiplied, this degrades sharply.
  No rotation or compaction exists.
- **Clock skew.** Both boxes currently agree (verified in sync), but nothing pins
  NTP and merge ordering would rest on `run_started_utc` / `run_finished_utc`.

## Sequencing

1. Decide §0 — is driver-host attribution worth it, given `node_id` exists?
2. Clone-test the anchor (§1) before committing to it.
3. Write the `stage_results` header migration — **without it the column cannot be
   added at all**.
4. Add a lock to `append_stub`, or declare the triage merge single-writer.
5. Then the column, then fetch-and-merge, then log collection.

Steps 3 and 4 are prerequisites, not follow-ups. Revision 1 scheduled neither.

## What revision 1 got wrong

Recorded because the pattern matters more than the instances.

- **Merge key** would have dropped 68% of `stage_results` rows — a data-destroying
  default, proposed in the name of protecting data.
- **Schema change** was impossible as written; the blocking constraint was never
  found.
- **The MAC critique** was marked "verified" on a fact that one further command
  disproves.
- **The positional-read hazard** named a file that resolves columns by name.
- **HMAC with a public salt** was ceremony that provided nothing over a bare hash,
  while the document claimed a property it also contradicted two lines later.
- **The opening motivation** proposed a column that may not answer the question it
  opened with, when an existing column already does.

Five of six are the same error: a plausible claim asserted without checking the
thing it depended on. The one exception — the entropy argument — was the only
part that was actually derived.
