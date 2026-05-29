# Live Linux Lab Failure Digest (20260529T064340Z)

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
- `PASS` `bootstrap_hosts`: all targeted nodes bootstrapped and compiled RustyNet successfully
- `PASS` `collect_pubkeys`: all targeted nodes exported WireGuard public keys successfully
- `PASS` `membership_setup`: primary exit applied signed membership updates successfully
- `PASS` `distribute_membership_state`: membership state distributed to all targeted peer nodes successfully
- `PASS` `issue_and_distribute_assignments`: signed assignments were issued and distributed to all targeted nodes successfully
- `PASS` `issue_and_distribute_traversal`: stage passed
- `PASS` `issue_and_distribute_dns_zone`: stage passed
- `PASS` `enforce_baseline_runtime`: all targeted nodes enforced baseline runtime successfully
- `PASS` `validate_baseline_runtime`: all targeted nodes connected to the network correctly under baseline validation
- `FAIL` `live_anchor`: stage failed

## Failure Focus

- first_failed_stage: `live_anchor`
- severity: `hard`
- rc: `1`
- likely_reason: [stage:live_anchor] failure digest: artifacts/live_lab/phase24-macos-smoke/20260525T222217Z/orchestrator/failure_digest.md
- full_log: `artifacts/live_lab/phase24-macos-smoke/20260525T222217Z/orchestrator/logs/live_anchor.log`
