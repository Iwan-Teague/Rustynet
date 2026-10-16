# Lab known issue ki-0001: exit_dns_failclosed_validation (intermittent, under root-cause analysis)

Status: OPEN. The check stays exactly as strict as it is. This record only lets the remedy ledger accept the failure while the product fix is built; it is not a waiver of the check.

What fails: the live-lab stage `exit_dns_failclosed_validation` fails on the lenovo host in about half of runs with
`<node>: tcp_block_pcap.txt contains DNS egress evidence; expected an empty blocked-path capture`.
The dependent stage `exit_nat_lifecycle_validation` (and the stages after it) are then skipped, which is why a failing run shows 37 passed and 33 skipped against 54 passed and 17 skipped in a passing run.

Evidence (lenovo-lab-90 triage): a full TCP/53 exchange from the exit guest to 1.1.1.1 (query `A? 3.debian.pool.ntp.org`, three A records returned) inside the 5 second capture window. The guest firewall had only `rustynet-dns-block-lan-udp` / `-tcp`. The probe to the LAN resolver got no response (correct). The guest resolver is the systemd-resolved stub on 127.0.0.1. The capture became line-exact with landing step 71; earlier runs passed vacuously because buffered capture lines were lost on SIGKILL.

Why this is not an ignore list: the 1.1.1.1 lookup is treated as a real off-tunnel DNS egress from the exit host until the root cause (which process emits it, why it reaches the physical NIC) is established and the product is patched. The row below expires on 2026-10-28 and allows 80 uses (raised from 40 on 2026-10-16 by the owner, who ordered the exact root cause found, a strict patch built and its fix verified by repeated live labs; lenovo hit the failure in 6 of its previous 10 runs, so the first cap was reached within a day), whichever comes first; after that the failure blocks relaunch again.

Fix tracking: root-cause analysis and a strict product patch (no loosening of the check) are in progress; when it lands, remove row ki-0001 and re-pin the registry.
