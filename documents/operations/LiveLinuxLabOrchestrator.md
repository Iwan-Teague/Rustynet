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
- `extra`: optional extra client

What runs with each topology:

- 2 nodes:
  - clean install
  - bootstrap
  - one-hop routing validation
- 3 nodes:
  - plus live exit handoff
- 4 or more nodes:
  - plus two-hop validation
  - plus LAN toggle / blind-exit validation
  - plus extended soak / reboot recovery

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
- live exit handoff
- live two-hop validation
- live LAN toggle validation
- local full gate suite (unless `--skip-gates`)

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
- `logs/<stage>.log`
- `verification/full_gate_suite_<timestamp>.log` when gates are enabled
- live test JSON reports written by the reused `scripts/e2e/` test scripts

The summary files show:

- node layout
- per-stage severity
- per-stage pass/fail/skip status
- return code
- log path
- stage description

## Usage

Interactive:

```bash
bash scripts/e2e/live_linux_lab_orchestrator.sh
```

Non-interactive, full five-node topology:

```bash
bash scripts/e2e/live_linux_lab_orchestrator.sh \
  --exit-target debian@192.168.18.49 \
  --client-target debian@192.168.18.50 \
  --entry-target ubuntu@192.168.18.52 \
  --aux-target fedora@192.168.18.51 \
  --extra-target mint@192.168.18.53 \
  --ssh-password-file /tmp/rustynet_ssh.pass \
  --sudo-password-file /tmp/rustynet_sudo.pass
```

Dry-run validation only:

```bash
bash scripts/e2e/live_linux_lab_orchestrator.sh \
  --exit-target debian@192.168.18.49 \
  --client-target debian@192.168.18.50 \
  --entry-target ubuntu@192.168.18.52 \
  --aux-target fedora@192.168.18.51 \
  --extra-target mint@192.168.18.53 \
  --ssh-password-file /tmp/rustynet_ssh.pass \
  --sudo-password-file /tmp/rustynet_sudo.pass \
  --skip-gates \
  --skip-soak \
  --dry-run
```

## Important flags

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

## Current limitation

The local full gate suite still validates the workspace using the repository's existing evidence/gate scripts.

That means the gate stage is faithful to the project’s current CI gates, but it is not yet rebinding every release-gate artifact to the exact orchestrator run automatically.

The live-lab stages do produce run-specific reports in the orchestrator report directory.

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
