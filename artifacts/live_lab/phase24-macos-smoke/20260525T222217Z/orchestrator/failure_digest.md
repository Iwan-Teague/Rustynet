# Live Linux Lab Failure Digest (20260528T202409Z)

- overall_status: `fail`
- report_dir: `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/phase24-macos-smoke/20260525T222217Z/orchestrator`
- node_count: `6`

## Condensed Checks

- `PASS` `preflight`: local prerequisites are ready
- `PASS` `prepare_source_archive`: deploy source archive prepared successfully
- `PASS` `verify_ssh_reachability`: stage passed
- `PASS` `prime_remote_access`: all targeted nodes accepted remote SSH and sudo priming
- `PASS` `macos_preflight_check`: stage passed
- `PASS` `cleanup_hosts`: all targeted nodes cleaned prior RustyNet state successfully
- `FAIL` `bootstrap_hosts`: bootstrap or compile failed on one or more targeted nodes (1/6 targeted nodes failed)

## Failure Focus

- first_failed_stage: `bootstrap_hosts`
- severity: `hard`
- rc: `1`
- likely_reason: [bootstrap] failed to reach cargo registry: https://index.crates.io/ 
- full_log: `artifacts/live_lab/phase24-macos-smoke/20260525T222217Z/orchestrator/logs/bootstrap_hosts.log`

### Failed Nodes

- `aux` `mac@192.168.0.210` (`client-3`): rc=1 reason=[bootstrap] failed to reach cargo registry: https://index.crates.io/  log=`artifacts/live_lab/phase24-macos-smoke/20260525T222217Z/orchestrator/state/parallel-bootstrap_hosts/aux.log` snapshot=`n/a`
