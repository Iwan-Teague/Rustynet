# LiveLab Run Matrix

## The ledgers — and which one is evidence

There are **two run matrices, one per orchestrator engine**. They share a schema
but are **not interchangeable**:

| ledger | engine | status |
| --- | --- | --- |
| [`live_lab_node_run_matrix.csv`](./live_lab_node_run_matrix.csv) | Rust `--node` | **ACTIVE** — appended by every `--node` run; the default source for coverage/tooling |
| [`live_lab_run_matrix.csv`](./live_lab_run_matrix.csv) | legacy bash orchestrator | **FROZEN ARCHIVE** — historical only; `--node` never appends here |

**Never read a stage result from one ledger as evidence for the other engine.**
The engines genuinely diverge. The archive records **52 `linux_stage_two_hop`
passes** (June 10–24, all bash) while the `--node` engine has **never once**
passed two-hop — a single blended file made those indistinguishable, and the
blend was read as "two-hop works" when the shipped engine had never proven it.
Splitting the ledgers makes the engine unambiguous by construction rather than
by footnote.

Routing is automatic and needs no flag: only the `--node` engine writes a node
stage plan into its report dir, and `append_live_lab_run_matrix_row`
(`crates/rustynet-cli/src/live_lab_run_matrix.rs`) routes on that marker.

[`live_lab_node_stage_results.csv`](./live_lab_node_stage_results.csv) is the
normalized node-level companion ledger for the `--node` engine. It records one
row per run × node × stage with fetched exact OS/version evidence. Use it—not the
Linux umbrella columns—to prove Debian, Rocky, Ubuntu, and Fedora separately.

**Defect — a per-OS stage column could read `fail` for a stage that was `skip`.
FIXED 2026-08-28 (W-FIX-3), forward-only.** The per-OS bootstrap columns
absorbed the run-scoped `preflight` stage, which shares their `bootstrap`
logical column, so a `preflight` failure wrote `fail` into
`linux_stage_bootstrap`, `macos_stage_bootstrap` **and**
`windows_stage_bootstrap` at once even though `bootstrap_hosts` never ran on any
node. Confirmed on `livelab-1784489499-db3ff1aaafe6` and
`livelab-1785005557-b7667cce46db`. This inflated the published Windows bootstrap
fail count from 3 to 5 and misdirected CP-4 triage for five weeks; see
[`active/WindowsNodeBootstrapTriageVerdict_2026-08-28.md`](./active/WindowsNodeBootstrapTriageVerdict_2026-08-28.md)
§0(c) for the evidence and §7.3 for the disposition.

Note the fix is **not** in `merge_status` (`live_lab_run_matrix.rs:2215-2231`):
ranking `fail` above `skip` is correct and was left alone. The bug was the
column FEED. Stages whose outcome describes the run rather than any OS's nodes
are now marked `run_scoped` in `live_lab_stage_registry.rs` and write neither a
`{platform}_stage_*` nor a `cross_os_*` column; the run's failure is carried by
`overall_result` + `first_failed_stage` as before. Four stages qualified —
`preflight` and `prepare_source_archive` (bootstrap columns), plus
`cross_network_substrate_setup` and `cross_network_preflight`, which were
poisoning `{platform}_stage_cross_network` the same way.

**Historical rows were NOT rewritten.** The ledgers are append-only evidence, so
every pre-fix row still reads exactly as the tooling wrote it — same forward-only
treatment the `traffic_test_matrix` de-aliasing got on 2026-07-27. When counting
across rows written before 2026-08-28, join any bootstrap or cross-network column
count against `live_lab_node_stage_results.csv` and check `first_failed_stage`
before quoting a number — the same "take the verdict from the stage's own
artifact, never from the column" rule AGENTS/CLAUDE §12.3 already imposes for
`two_hop`.

## Purpose

Rustynet must be proven in mixed real-world topologies, not only Debian-only
happy paths. Record every meaningful LiveLab run so regressions can be traced
to commits and so OS, role, and stage gaps stay visible.

## When To Append A Row

The following paths append one row automatically at completion:

- `ops vm-lab-orchestrate-live-lab` (the Rust `--node` engine — the only
  writer since the W5.7 bash-orchestrator deletion; the bash EXIT-trap writer
  and the retired `vm-lab-run-live-lab`/`vm-lab-iterate-live-lab` wrappers are
  gone)

The writer also emits the exact row for the current run at
`<report_dir>/state/live_lab_run_matrix_row.csv`. Focused macOS, Windows, or
Linux role validation scripts that bypass these paths still require a manual row
before claiming a run is green, regressed, unsupported, or at platform parity.

Rust `--node` runs also emit
`<report_dir>/state/live_lab_node_stage_results.csv` and upsert the same rows
into the normalized repository ledger. Missing/unrecognized OS version data or
missing planned-stage outcomes fail evidence finalization.

## Required Row Rules

- One row per run attempt.
- One normalized row per participating node and planned stage. Exact fetched
  `os_family` + `os_version` are mandatory; generic `linux` is rejected.
- `git_commit` must be the exact deployed and tested commit.
- `git_dirty_state` must be `clean` or `dirty:<short reason>`.
- `report_dir`, `failure_digest_path`, and `evidence_bundle_path` must point at
  artifacts generated by this run when available.
- Mark unsupported or intentionally skipped cells `skip` or `na`, never blank.
- Mark untested cells `not_run`.
- Mark blocked prerequisites `blocked`.
- Use `notes` and `regression_notes` for why a role or stage failed or was
  skipped.
- If something worked in the past and fails now, set
  `regression_reference_commit` to the last known good commit.
- The Rust writer reads the current CSV header and writes values by column name.
  When built-in identity columns are missing, it extends the header and leaves
  older rows intact.
- Network-profile provenance columns (`network_profile_id`,
  `network_profile_digest`, `network_management_mode`,
  `network_scenario_substrate`, `network_address_family`,
  `network_internet_mode`, `network_evidence_path`) are filled from the
  immutable `orchestration/network_profile.json` record the orchestrator
  writes at launch (see
  [LiveLabVmConnectivityRulebook.md](./LiveLabVmConnectivityRulebook.md) §10).
  Legacy rows without a record stay blank; new runs always carry them.

## Status Vocabulary

Use only these status values in result cells:

- `pass`
- `fail`
- `skip`
- `blocked`
- `not_run`
- `na`
- `unknown`

## Coverage Shape

The CSV tracks:

- OS presence: Linux, macOS, Windows.
- Role proof per OS: client, admin, exit, blind_exit, relay, anchor.
- Stage proof per OS: bootstrap, membership, assignments, baseline runtime,
  anchor, relay service lifecycle, exit handoff, LAN toggle, two-hop, role
  switch matrix, managed DNS, mixed topology, reboot recovery, extended soak,
  chaos.
- Cross-OS proof: membership convergence, peer visibility, direct path, relay
  path, exit path, DNS, LAN toggle, role switch, anchor bundle pull/enrollment,
  Windows named-pipe and DPAPI custody, macOS Keychain and PF killswitch.
- Node identity per OS role: alias, node ID, and target for client, admin,
  exit, blind_exit, relay, and anchor roles.

The normalized companion CSV additionally tracks:

- exact distro/platform family: `debian`, `rocky`, `ubuntu`, `fedora`, `macos`,
  or `windows`;
- fetched OS version and architecture;
- node alias, node ID, assigned role, stage, result, evidence path, and failure
  detail;
- `stage_scope=node` for per-node proof and `stage_scope=topology` when the node
  participated in a whole-lab proof such as an all-pairs traffic matrix.

## Current Truth

This ledger records evidence; it does not make unsupported paths supported. As
of 2026-05-27, Linux anchors have live traffic validation. macOS and Windows
anchor coverage can still be dry-run or non-mutating depending on the stage.
Mark those cells honestly.

## Operator Notes

- Prefer the standard report directory emitted by the wrapper as the evidence
  root.
- Use the exact command line in `run_command`, CSV-escaped when it contains
  commas.
- Keep the ledger append-only. If a row needs correction, append a later
  superseding row and explain it in `notes`.
- The CSV is intentionally diffable instead of `.xlsx` so agents can update it
  safely during code review and merge work.
