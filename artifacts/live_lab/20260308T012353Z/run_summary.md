# Live Linux Lab Orchestrator Summary (20260308T012353Z)

- overall_status: `fail`
- network_id: `rn-live-lab-20260308T012353Z`
- report_dir: `/Users/iwanteague/Desktop/Rustynet/artifacts/live_lab/20260308T012353Z`

## Nodes

- `exit`: `debian@192.168.18.49` (`exit-1`, bootstrap role `admin`)
- `client`: `debian@192.168.18.50` (`client-1`, bootstrap role `client`)
- `entry`: `ubuntu@192.168.18.52` (`client-2`, bootstrap role `client`)
- `aux`: `fedora@192.168.18.51` (`client-3`, bootstrap role `client`)
- `extra`: `mint@192.168.18.53` (`client-4`, bootstrap role `client`)

## Stages

- `preflight` [hard] -> `pass` (rc=0)
  log: `/Users/iwanteague/Desktop/Rustynet/artifacts/live_lab/20260308T012353Z/logs/preflight.log`
  detail: verify local prerequisites
- `prepare_source_archive` [hard] -> `pass` (rc=0)
  log: `/Users/iwanteague/Desktop/Rustynet/artifacts/live_lab/20260308T012353Z/logs/prepare_source_archive.log`
  detail: package local source tree for remote install
- `prime_remote_access` [hard] -> `pass` (rc=0)
  log: `/Users/iwanteague/Desktop/Rustynet/artifacts/live_lab/20260308T012353Z/logs/prime_remote_access.log`
  detail: push sudo credentials to all targets
- `cleanup_hosts` [hard] -> `fail` (rc=255)
  log: `/Users/iwanteague/Desktop/Rustynet/artifacts/live_lab/20260308T012353Z/logs/cleanup_hosts.log`
  detail: remove prior RustyNet state from targets
