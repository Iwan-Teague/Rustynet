# Live Linux Soak Summary (2026-03-08)

Commit under test: `2e38107` (`Checkpoint full gate suite pass and live evidence`)

## Full gate suite

- Result: `PASS`
- Evidence log: `artifacts/verification/full_gate_suite_main_20260308T000436Z.log`

## Live soak tests

### 1. Two-hop baseline before reboot

- Result: `PASS`
- Evidence:
  - `artifacts/phase10/live_linux_two_hop_soak_pre_reboot_report.json`
  - `artifacts/phase10/source/live_linux_two_hop_soak_pre_reboot.log`

Checks passed:

- client exit is entry relay
- entry relay exits via final exit
- entry relay serves as exit
- final exit serves as exit
- client route pinned to `rustynet0`
- second client route pinned to `rustynet0`
- entry peer visibility correct
- no plaintext passphrase artifacts

### 2. Extended live exit handoff under load

- Result: `PASS`
- Evidence:
  - `artifacts/phase10/live_linux_exit_handoff_soak_report.json`
  - `artifacts/phase10/source/live_linux_exit_handoff_soak.log`
  - `artifacts/phase10/source/live_linux_exit_handoff_soak_monitor.log`

Checks passed:

- handoff reconvergence
- no route leak during handoff
- no restricted safe mode
- new exit endpoint visible
- both exits kept NAT active

### 3. LAN toggle / blind-exit enforcement rerun

- Result: `PASS`
- Evidence:
  - `artifacts/phase10/live_linux_lan_toggle_soak_report.json`
  - `artifacts/phase10/source/live_linux_lan_toggle_soak.log`

Checks passed:

- LAN off blocks
- LAN on allows
- LAN off again blocks
- blind-exit denial enforced
- no plaintext passphrase artifacts

## Reboot recovery checks

### Exit node `debian@192.168.18.49`

- Reboot command issued: `sudo systemctl reboot`
- Pre-reboot boot ID: `d8cb2101-8cd7-45de-b1d9-d58c4575d36f`
- Post-reboot boot ID: `d7b0afaa-9c49-4257-b322-115d7e94e8f9`
- Result: `PASS`

Post-reboot recovery validation:

- Alternate-client two-hop rerun passed
- Evidence:
  - `artifacts/phase10/live_linux_two_hop_soak_post_exit_reboot_report.json`
  - `artifacts/phase10/source/live_linux_two_hop_soak_post_exit_reboot.log`

### Client `debian@192.168.18.50`

- Reboot command issued: `sudo systemctl reboot`
- Pre-reboot boot ID: `0a6f02c3-1c0c-4a94-a989-8ec46deed39e`
- Result: `FAIL`

Observed behavior:

- host never returned on SSH within the wait budget
- direct SSH probe returned `Host is down`
- ARP entry for `192.168.18.50` became incomplete
- SSH port scan over `192.168.18.1-254` found only:
  - `192.168.18.49`
  - `192.168.18.51`
  - `192.168.18.52`
  - `192.168.18.53`

Assessment:

- This is a real live-lab blocker surfaced by the soak.
- It is not yet attributable to product code with confidence because the node disappeared from the network entirely rather than returning with a service-level failure.
- Further diagnosis requires VM-console access or manual power-on/recovery of `192.168.18.50`.

## Net result

- Full gate suite: `PASS`
- Live steady-state and handoff/two-hop/LAN tests: `PASS`
- Exit reboot recovery: `PASS`
- Client reboot recovery (`192.168.18.50`): `FAIL`

Current conclusion:

- The current build is strong in steady-state and on live routing/handoff behavior across the remaining Linux lab nodes.
- The current unresolved live-network issue is reboot recovery for client `192.168.18.50`, which dropped off the network after reboot and prevented completion of the original client+exit reboot retest.
