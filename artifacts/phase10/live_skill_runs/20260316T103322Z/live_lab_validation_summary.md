# Rustynet Live-Lab Validation Run

## Validator Commands

| Validation | Exit Code | Report Path |
| --- | --- | --- |
| control_surface_exposure | 0 | `/Users/iwanteague/Desktop/Rustynet/artifacts/phase10/live_skill_runs/20260316T103322Z/live_linux_control_surface_exposure_report.json` |
| server_ip_bypass | 0 | `/Users/iwanteague/Desktop/Rustynet/artifacts/phase10/live_skill_runs/20260316T103322Z/live_linux_server_ip_bypass_report.json` |
| endpoint_hijack | 0 | `/Users/iwanteague/Desktop/Rustynet/artifacts/phase10/live_skill_runs/20260316T103322Z/live_linux_endpoint_hijack_report.json` |

## Consolidated Outputs

- Findings report: `/Users/iwanteague/Desktop/Rustynet/artifacts/phase10/live_skill_runs/20260316T103322Z/live_lab_findings.md`
- Findings generation exit code: `0`
- Schema validation report: `/Users/iwanteague/Desktop/Rustynet/artifacts/phase10/live_skill_runs/20260316T103322Z/live_lab_schema_validation.md`
- Schema validation exit code: `0`
- Coverage promotion report: `/Users/iwanteague/Desktop/Rustynet/artifacts/phase10/live_skill_runs/20260316T103322Z/live_lab_coverage_promotion.md`
- Coverage promotion exit code: `0`

### control_surface_exposure

- Command: `/Users/iwanteague/Desktop/Rustynet/scripts/e2e/live_linux_control_surface_exposure_test.sh --ssh-password-file /tmp/fake-ssh.pass --sudo-password-file /tmp/fake-sudo.pass --report-path /Users/iwanteague/Desktop/Rustynet/artifacts/phase10/live_skill_runs/20260316T103322Z/live_linux_control_surface_exposure_report.json --log-path /Users/iwanteague/Desktop/Rustynet/artifacts/phase10/live_skill_runs/20260316T103322Z/live_linux_control_surface_exposure_report.log --exit-host debian@192.168.18.49 --client-host ubuntu@192.168.18.52 --entry-host ubuntu@192.168.18.52 --aux-host fedora@192.168.18.51 --extra-host mint@192.168.18.53 --probe-host fedora@192.168.18.51`
- Exit code: `0`
- stderr:
```text
[no stderr]
```

### server_ip_bypass

- Command: `/Users/iwanteague/Desktop/Rustynet/scripts/e2e/live_linux_server_ip_bypass_test.sh --ssh-password-file /tmp/fake-ssh.pass --sudo-password-file /tmp/fake-sudo.pass --report-path /Users/iwanteague/Desktop/Rustynet/artifacts/phase10/live_skill_runs/20260316T103322Z/live_linux_server_ip_bypass_report.json --log-path /Users/iwanteague/Desktop/Rustynet/artifacts/phase10/live_skill_runs/20260316T103322Z/live_linux_server_ip_bypass_report.log --client-host ubuntu@192.168.18.52 --probe-host fedora@192.168.18.51`
- Exit code: `0`
- stderr:
```text
[no stderr]
```

### endpoint_hijack

- Command: `/Users/iwanteague/Desktop/Rustynet/scripts/e2e/live_linux_endpoint_hijack_test.sh --ssh-password-file /tmp/fake-ssh.pass --sudo-password-file /tmp/fake-sudo.pass --report-path /Users/iwanteague/Desktop/Rustynet/artifacts/phase10/live_skill_runs/20260316T103322Z/live_linux_endpoint_hijack_report.json --log-path /Users/iwanteague/Desktop/Rustynet/artifacts/phase10/live_skill_runs/20260316T103322Z/live_linux_endpoint_hijack_report.log --client-host ubuntu@192.168.18.52 --rogue-endpoint-ip 203.0.113.44`
- Exit code: `0`
- stderr:
```text
[no stderr]
```
