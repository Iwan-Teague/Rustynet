# Live Linux Lab Orchestrator

Script: `scripts/e2e/live_linux_lab_orchestrator.sh`

## Purpose

This script automates the live Linux lab workflow that was previously being run manually:

- prompt for lab machines
- clean existing RustyNet state from those machines
- install the current local RustyNet source tree on each machine
- bootstrap a shared network
- make one machine the primary exit node
- route client traffic through that exit node
- run the baseline live validations
- optionally run the local full gate suite
- optionally run an extended soak, including reboot recovery checks
- run explicit hard-fail cross-network remote-exit stages after the current live suite
- emit structured reports with explicit hard-fail and soft-fail stages

## Target topology

Minimum supported topology:

- `exit`: primary exit node
- `client`: primary client node

Recommended topology for the full live suite:

- `exit`: primary exit node
- `client`: primary client node
- `entry`: entry relay / alternate exit
- `aux`: auxiliary client / blind-exit target
- `extra`: extra client required for the full Linux release-gate evidence path

What runs with each topology:

- 2 nodes:
  - clean install
  - bootstrap
  - one-hop routing validation
  - live managed-DNS validation
- 3 nodes:
  - plus live exit handoff
- 4 or more nodes:
  - plus two-hop validation
  - plus LAN toggle / blind-exit validation
  - plus extended soak / reboot recovery
- 5 nodes:
  - plus controlled role-switch validation
  - plus commit-bound Linux fresh-install OS matrix report generation
  - plus local full gate suite with fresh-install release-gate evidence rebound to the current run
  - plus the full explicit cross-network remote-exit validation stages

Security note:

- when the topology has only 4 nodes, the orchestrator now skips the 5-node-only release-gate attestation path instead of pretending to run a complete full-gate evidence flow
- the `local_full_gate_suite` stage only runs when `entry`, `aux`, and `extra` are all present

## Security model

The orchestrator reuses the hardened live-lab helpers and existing signed-assignment flows.

It does not introduce alternate product control paths.

It uses the same secure primitives already exercised in the lab:

- owner-only password files
- signed membership updates
- signed assignment issuance
- daemon-enforced role coupling
- secure cleanup of materialized signing passphrases on remote hosts
- no plaintext passphrase acceptance in the validation path

## Parallel execution model

The orchestrator no longer staggers independent per-host SSH/SCP work unnecessarily.

The following stages now execute one worker per target in parallel:

- `prime_remote_access`
- `cleanup_hosts`
- `bootstrap_hosts`
- `collect_pubkeys`
- `distribute_membership_state` for non-exit peers
- `issue_and_distribute_assignments`
- `enforce_baseline_runtime`
- `validate_baseline_runtime`

Security and determinism constraints for parallel work:

- each worker gets its own `known_hosts` file inside the live-lab work directory, seeded from the operator-supplied pinned host-key file
- each worker writes its own stage log before the parent aggregates output
- signed membership setup and assignment issuance on the primary exit remain single-authority serialized steps
- exit route advertisement remains serialized after per-host runtime enforcement

This keeps the expensive host-local work concurrent without introducing shared-state races in SSH host-key tracking or signed-control-plane mutation. TOFU host-key acceptance is intentionally disabled.

## Hard-fail vs soft-fail stages

Hard-fail stages stop the run immediately with a non-zero exit code.

Default hard-fail stages:

- local preflight
- source packaging
- remote cleanup
- remote bootstrap
- membership setup
- assignment issuance/distribution
- baseline runtime enforcement
- baseline routing validation
- controlled role switch validation
- live exit handoff
- live two-hop validation
- live LAN toggle validation
- live managed-DNS validation
- fresh install OS matrix report generation
- local full gate suite (unless `--skip-gates`)
- cross-network preflight (time skew + host capabilities)
- cross-network direct remote-exit validation
- cross-network relay remote-exit validation
- cross-network failback / roaming validation
- cross-network traversal adversarial validation
- cross-network remote-exit DNS validation
- cross-network remote-exit soak validation
- cross-network NAT matrix coverage validation

Soft-fail stages continue and are recorded in the summary.

Default soft-fail stage:

- extended soak / reboot recovery

If you want reboot/soak failures to terminate the run, use:

- `--reboot-hard-fail`

## Reports

Each run writes a dedicated report directory under:

- `artifacts/live_lab/<timestamp>/`

Important outputs:

- `run_summary.json`
- `run_summary.md`
- `failure_digest.json`
- `failure_digest.md`
- `logs/<stage>.log`
- `verification/full_gate_suite_<timestamp>.log` when gates are enabled
- live test JSON reports written by the reused `scripts/e2e/` test scripts
- `fresh_install_os_matrix_report.json` in the run directory and the canonical `artifacts/phase10/` path when the full Linux evidence path runs
- canonical fresh-install matrix inputs rebound under `artifacts/phase10/source/fresh_install_os_matrix/` so the committed report no longer depends on gitignored `artifacts/live_lab/...` evidence paths
- cross-network reports written in the run directory for each remote-exit suite

The summary files show:

- node layout
- per-stage severity
- per-stage pass/fail/skip status
- return code
- log path
- stage description
- run start timestamp
- run finish timestamp
- elapsed wall-clock runtime

The terminal output also prints the run start time immediately when the script is invoked and prints total elapsed runtime again at the end of the run or dry-run.

The failure digest files are intentionally smaller and optimized for triage:

- one-line condensed result per completed stage
- a single first-failure focus block
- failing node labels/targets for parallel stages
- most likely failure reason extracted from the relevant worker or stage log
- direct path to the full log when deeper inspection is needed

For reboot/soak failures, the digest now prefers the structured reboot recovery report over the raw stage log so the first failure reason reflects the actual failed checks instead of a generic stage trailer.

On any hard-fail stage, the orchestrator also prints the `failure_digest.md` path immediately in the terminal output so you can jump straight to the compact triage view.

For cross-network stage failures, the orchestrator now also captures a forensic bundle under:

- `artifacts/live_lab/<timestamp>/forensics/<stage>/<timestamp>/`

The bundle captures redacted status/routes/endpoints, nftables ruleset, `ss` output, service status, and recent `journalctl` tails from each configured node.

## Cross-Network Remote-Exit Stages

The orchestrator now includes six explicit cross-network remote-exit stages at the end of the current live workflow:

- `cross_network_preflight`
- `cross_network_direct_remote_exit`
- `cross_network_relay_remote_exit`
- `cross_network_failback_roaming`
- `cross_network_traversal_adversarial`
- `cross_network_remote_exit_dns`
- `cross_network_remote_exit_soak`
- `cross_network_nat_matrix`

Current behavior:

- `cross_network_preflight`
  - verifies host clocks stay within a strict skew bound before cross-network validators run
  - verifies required binaries/services and daemon socket readiness on each host
  - verifies each host has a global IPv4 address, default IPv4 route, and local hostname resolution
  - verifies no plaintext passphrase files are present on each host
  - verifies signed assignment/traversal/trust runtime state with first-class `rustynet assignment|traversal|trust verify` cryptographic commands (signature, freshness, watermark replay/rollback checks)
  - verifies signed DNS-zone bundles with `rustynet dns zone verify` before cross-network mutation stages
  - generates one discovery bundle per host and validates it with strict schema/secret/custody checks before any cross-network validator executes
- `cross_network_direct_remote_exit`
  - runs a real validator that provisions a two-node direct remote-exit path using signed assignments, verifies full-tunnel routing, and reuses the server-IP bypass validator to prove leak resistance and narrow bypass scope
  - still fails closed if the measured topology does not provide credible cross-network proof, for example when the client and exit underlay addresses are on the same local prefix
- `cross_network_relay_remote_exit`
  - runs a real three-node validator that provisions a client -> relay -> exit chain through signed assignments, verifies relay and final-exit steady state, and reuses the server-IP bypass validator to prove leak resistance and narrow bypass scope
  - still fails closed if the measured topology cannot credibly prove a cross-network claim
- `cross_network_failback_roaming`
  - runs a real validator that first proves the relay path, then measures relay -> direct failback and signed endpoint-roam recovery on the live path
  - still fails closed if failback timing, endpoint adoption, or post-roam leak resistance cannot be proven
- `cross_network_traversal_adversarial`
  - runs a real validator that combines local signed traversal tamper/replay regression tests with live rogue-endpoint denial and control-surface exposure checks
- `cross_network_remote_exit_dns`
  - runs a real validator that first proves the direct remote-exit path, then validates managed DNS issuance, split-DNS resolution, and fail-closed stale-bundle behavior on that remote-exit client
- `cross_network_remote_exit_soak`
  - runs a real validator that bootstraps direct remote-exit, samples runtime health over a timed soak window, and re-runs server-IP bypass/leak checks after soak
  - fails closed unless soak evidence proves stability, no underlay leak before and after soak, narrow bypass scope, cross-network topology credibility, and no plaintext passphrase files
- `cross_network_nat_matrix`
  - validates that the run produced schema-valid, pass-status evidence for every required NAT profile across every cross-network suite
  - fails closed if any suite/profile combination is missing

Topology requirements for the cross-network stages:

- `cross_network_preflight`
  - requires `exit` and `client`
- `cross_network_direct_remote_exit`
  - requires `exit` and `client`
- `cross_network_relay_remote_exit`
  - requires `exit`, `client`, and either `entry` or `aux`
- `cross_network_failback_roaming`
  - requires `exit`, `client`, and either `entry` or `aux`
- `cross_network_traversal_adversarial`
  - requires `exit`, `client`, and either `aux` or `entry`
- `cross_network_remote_exit_dns`
  - requires `exit` and `client`
- `cross_network_remote_exit_soak`
  - requires `exit` and `client`
- `cross_network_nat_matrix`
  - requires completed cross-network report artifacts in the run directory

For parallel stages, the stage log also contains worker-delimited blocks so you can see:

- which node failed
- the exact worker output for that node
- whether the stage failed because of one host or multiple hosts

## Usage

Interactive:

```bash
bash scripts/e2e/live_linux_lab_orchestrator.sh
```

When launched interactively with no targets or explicit `--profile`, the script now asks whether to use the default saved VM lab profile:

- default profile: `profiles/live_lab/default_four_node.env`
- answer `yes`: load that profile immediately
- answer `no`: continue with the manual target prompts

Saved profile:

```bash
bash scripts/e2e/live_linux_lab_orchestrator.sh \
  --profile profiles/live_lab/default_four_node.env
```

Tracked lab profiles:

- `profiles/live_lab/default_four_node.env`
  - default four-node topology that avoids the unstable `192.168.18.50` VM
- `profiles/live_lab/default_five_node.env`
  - full five-node topology for release-gate evidence runs using the replacement Debian node `192.168.18.65`

Source selection:

- default: package the current local working tree
- interactive toggle: ask whether to update from latest git instead of the local working tree
- if you answer `yes`, the script fetches `origin`, prints the available branch names, and lets you choose by number or branch name
- explicit flags:
  - `--source-mode working-tree`
  - `--source-mode local-head`
  - `--source-mode origin-main`
  - `--use-local-head`
  - `--use-origin-main`
  - `--repo-ref <ref>` for an explicit git ref

Important:

- `working-tree` can include local uncommitted changes
- `local-head` uses the latest local commit only
- `origin-main` fetches and archives the latest committed remote `main`
- interactive branch selection can also deploy other fetched remote branches such as `origin/testing`
- if you want every VM on the latest committed repo state, use `origin-main`
- formal commit-bound gate evidence is fail-closed on provenance drift:
  - the live evidence reports are stamped with the deployed commit, not merely local workspace `HEAD`
  - the local full gate suite refuses mixed-source attestation when the deployed commit differs from local `HEAD`
  - the fresh-install OS matrix report refuses dirty working-tree provenance for commit-bound evidence

Non-interactive, full five-node topology:

```bash
bash scripts/e2e/live_linux_lab_orchestrator.sh \
  --exit-target debian@192.168.18.49 \
  --client-target debian@192.168.18.65 \
  --entry-target ubuntu@192.168.18.52 \
  --aux-target fedora@192.168.18.51 \
  --extra-target mint@192.168.18.53 \
  --ssh-known-hosts-file ~/.ssh/known_hosts \
  --ssh-identity-file ~/.ssh/rustynet_lab_ed25519
```

Dry-run validation only:

```bash
bash scripts/e2e/live_linux_lab_orchestrator.sh \
  --exit-target debian@192.168.18.49 \
  --client-target debian@192.168.18.65 \
  --entry-target ubuntu@192.168.18.52 \
  --aux-target fedora@192.168.18.51 \
  --extra-target mint@192.168.18.53 \
  --ssh-known-hosts-file ~/.ssh/known_hosts \
  --ssh-identity-file ~/.ssh/rustynet_lab_ed25519 \
  --skip-gates \
  --skip-soak \
  --dry-run
```

## Important flags

- `--profile <path>`
  - loads a saved `.env`-style lab profile
  - CLI flags still win if both are provided
  - do not store private-key paths for shared operator environments unless you control profile file permissions
- `--ssh-identity-file <path>`
  - required for non-interactive runs
  - must be a regular file with owner-only permissions (`0400` or `0600`)
  - password-based SSH/sudo transport is intentionally removed from active execution paths
- `--ssh-known-hosts-file <path>`
  - supplies the pinned SSH host-key file used for all worker SSH/SCP sessions
  - defaults to `~/.ssh/known_hosts` if it exists
  - must not be a symlink or group/world writable
- `--source-mode <working-tree|local-head|origin-main>`
  - selects what source archive gets installed on the lab machines
- `--use-origin-main`
  - shorthand for `--source-mode origin-main`
- `--use-local-head`
  - shorthand for `--source-mode local-head`
- `--skip-gates`
  - skips the local full gate suite stage
- `--skip-soak`
  - skips the extended soak and reboot recovery stage
- `--reboot-hard-fail`
  - promotes reboot/soak failures to hard failures
- `--repo-ref <ref>`
  - archives a git ref instead of the current working tree
- `--report-dir <path>`
  - writes reports to an explicit location
- `--traversal-ttl-secs <seconds>`
  - sets traversal endpoint-hint TTL used by orchestrator-issued signed traversal bundles
  - constrained to `1..120` to match control-plane security bounds; higher values fail closed
- `--cross-network-nat-profiles <csv>`
  - runs the cross-network validation suite once per NAT profile label
  - first profile writes canonical report names; additional profiles write suffixed report/log artifacts
- `--cross-network-required-nat-profiles <csv>`
  - defines the NAT profiles that must be present for matrix validation pass
- `--cross-network-impairment-profile <profile>`
  - applies a deterministic stage-scoped `tc netem` impairment profile (`none`, `latency_50ms_loss_1pct`, `latency_120ms_loss_3pct`, `loss_5pct`) to `rustynet0` on participating hosts and tags each cross-network report with that profile
  - impairment cleanup is mandatory; cleanup failure is fail-closed for the stage
- `--cross-network-max-time-skew-secs <seconds>`
  - strict maximum allowed per-host clock skew before cross-network stages start
- `--cross-network-discovery-max-age-secs <seconds>`
  - strict maximum allowed age for preflight discovery bundles
- `--cross-network-signed-artifact-max-age-secs <seconds>`
  - strict maximum allowed age for signed assignment/traversal/trust/dns runtime artifacts in cross-network preflight

## Current limitation

The local full gate suite still validates the local workspace at `HEAD`.

The orchestrator now regenerates the Linux fresh-install OS matrix report from the current live run before calling `fresh_install_os_matrix_release_gate.sh`, but it does not attempt to rewrite unrelated historical artifacts outside that evidence path.

## Validation added for profile-driven runs

The orchestrator now fails early on obvious topology mistakes before SCP/SSH work starts:

- structurally invalid IPv4 literals such as `192.168.18.999`
- duplicate hosts assigned to multiple labels, such as using the same VM for both `entry` and `aux`

Saved profiles also remove most retyping mistakes for valid-but-wrong addresses such as `192.169.18.49`.

That is intentional. The script assumes each label is a distinct machine unless the code is explicitly changed to support shared-role hosts.

## Recommended operating pattern

For fast lab checks:

1. run the orchestrator with `--skip-gates --skip-soak`
2. confirm the live install and baseline tests pass
3. rerun without `--skip-gates`
4. rerun without `--skip-soak` when you want reboot/soak coverage

For release-style lab validation:

1. run the full orchestrator with all stages enabled
2. inspect `run_summary.md`
3. inspect the individual failing stage log if any stage is not `pass`
