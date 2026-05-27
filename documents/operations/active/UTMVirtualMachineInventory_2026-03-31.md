# UTM Virtual Machine Inventory

Last updated:
`2026-05-21T20:33:00Z`

Repository root:
`workspace root`

Purpose:
- keep a last-known local record of the UTM Debian headless lab VMs and the
  local Windows 11 validation guest on this Mac,
- record parent-device context,
- record current SSH operator key material by path and fingerprint,
- avoid storing private key contents in the document.
- provide a human-readable companion to the machine-readable inventory at
  `documents/operations/active/vm_lab_inventory.json`
  used by `rustynet-cli ops vm-lab-*`.

## Parent Device

- Parent device: `iwan’s MacBook Pro`
- Local host name: `Iwans-MacBook-Pro`
- Hostname: `Mac`
- OS: `macOS 26.3.1 (a)` build `25D771280a`
- Architecture: `arm64`
- Active parent interface at time of capture: `en0`
- Last known parent IP on active interface: `192.168.0.20/24`
- Last known parent network SSID: unavailable from non-privileged local queries on this host
- UTM bundle root:
  `/Users/iwan/Library/Containers/com.utmapp.UTM/Data/Documents`

## SSH Operator Key

Current discovered lab operator key:

- Private key path: `~/.ssh/rustynet_lab_ed25519`
- Public key path: `~/.ssh/rustynet_lab_ed25519.pub`
- Key type: `ED25519`
- Fingerprint:
  `SHA256:0PhLS1UhWcVrtnxquTqQxotOlh3nch/uXwmrTF1nKbE`
- Key comment:
  `rustynet-live-lab-20260324`
- Public key:

```text
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJt+TYbMCSyKvPfiT0SunCF/2r6VjFPnBNsMGEv+fIfZ rustynet-live-lab-20260324
```

Security note:
- The private key contents are intentionally not duplicated into this document.
- This pass rehydrated the documented lab key path from a freshly generated local copy because the file was missing on disk.
- If you want a fresh per-lab or per-VM keypair, generate it separately and update this inventory with the new path and fingerprint.

## Inventory Notes

- The five Debian lab nodes and the local Windows 11 validation guest are all
  UTM `QEMU` guests.
- The Debian lab nodes are configured as `aarch64` Debian/Linux guests with
  `2048 MB` memory.
- UTM currently reports one shared network interface per VM in the configuration record.
- A macOS 26.4.1 (arm64) guest (`macos-utm-1`) was added 2026-05-21 using the
  Apple Virtualization framework backend (`Backend = Apple` in UTM config). This
  guest uses a separate bridge (`bridge101`, `192.168.65.0/24`) rather than the
  QEMU shared network (`bridge100`, `192.168.64.0/24`) used by all other guests.
  Remote Login (SSH) enabled; operator credentials are `mac` / `tempo` matching
  the fleet standard. Rustynet source directory target: `/Users/mac/Rustynet`.
- Live guest-agent verification was performed with UTM `query ip` on `2026-04-07`; live SSH reachability was rechecked in this pass over the IPv4 SSH endpoints because they were the stable SSH form on this host.
- The per-VM IPv4s below are live-confirmed from the running guests, not inferred from hostname history.
- One extra UTM-style historical IP, `192.168.64.18`, still exists in older host-key history but could not be tied to the current five bundles during this pass.

## Probe-and-Recover Runbook

When an orchestrator retry fails at `prime_remote_access`, `cleanup_hosts`,
or `verify_ssh_reachability` because one or more lab VMs are stuck (TCP/22
times out from the host even though `arp -a` shows the VM is alive on the
LAN), use the probe-and-recover script:

```
scripts/vm_lab/probe_and_recover_local_utm.sh
```

What it does (each step idempotent):

1. Calls `cargo run --quiet --bin rustynet-cli -- ops vm-lab-discover-local-utm`
   to enumerate every registered UTM VM, its DHCP-assigned IP, and the
   current SSH-port status.
2. Prints a per-VM table with platform, live IP, and SSH:22 reachability.
3. For each Linux VM whose SSH port is NOT open, invokes
   `utmctl exec <vm> --cmd /usr/bin/sudo nft flush ruleset` followed by
   `systemctl stop rustynetd` and `rustynetd-privileged-helper`. This path
   does not depend on SSH — it travels the qemu-guest-agent socket UTM
   exposes for QEMU guests. Recovery is automatic only for Linux guests
   because UTM's Apple Virtualization backend does not surface
   `utmctl exec` for macOS guests.
4. Re-probes TCP/22 on every VM after recovery and prints a final summary.

Common stuck cause: a previous lab run's `restrict_permanent` killswitch
table is still installed inside the guest. nftables on the OUTPUT chain
has policy `drop` plus narrow allowlists tied to the prior management
CIDR (e.g., `192.168.65.0/24`); after a re-IP (DHCP renewal, network mode
change, fresh bridge), inbound SSH still reaches the guest's listener but
the SYN-ACK can't leave because the new source IP is not in the allowed
set. `nft flush ruleset` removes the killswitch and reopens the path.

Manual recovery for macOS / Windows guests (UTM Apple Virtualization
backend does not expose `utmctl exec`) — open the guest via UTM serial
console / VNC / RDP and run:

- macOS:
  ```
  sudo launchctl bootout system/com.rustynet.daemon 2>/dev/null || true
  sudo launchctl bootout system/com.rustynet.privileged-helper 2>/dev/null || true
  sudo pfctl -F all -d
  ```
- Windows:
  ```
  sc.exe stop RustyNet
  sc.exe stop RustyNetPrivilegedHelper
  ```

After recovery, regenerate `known_hosts` if the lab profile's pinned
known_hosts file references the old IPs:

```
KH=profiles/live_lab/<your_known_hosts_file>
> "$KH"
for ip in <new IPs>; do
  ssh-keyscan -T 5 -t rsa,ed25519 "$ip" 2>/dev/null >> "$KH"
done
```

Then update the matching lab profile (`.env` file in `profiles/live_lab/`)
with the new `*_TARGET=` values and re-run the orchestrator.

## Machine-Readable Inventory Model

The companion inventory file at
`documents/operations/active/vm_lab_inventory.json`
is now the operator-facing source for `rustynet-cli ops vm-lab-*`.

Entry model:

- `alias`: stable operator label such as `debian-headless-1`
- `ssh_target`: SSH alias, hostname, or `user@host` target that is reachable from this Mac
- `ssh_user`: optional default SSH username override
- `ssh_password`: optional bootstrap-only password used to refresh SSH keys or recover access
- `include_in_all`: optional boolean that excludes recovery-only rows from `--all` selection when set to `false`
- `node_id`: Rustynet node identity used for topology/state issuance
- `lab_role`: orchestration role such as `exit`, `client`, `relay`, `aux`, or `extra`
- `mesh_ip`: last-known intended Rustynet mesh IP for topology/state records
- `exit_capable`: whether the node is expected to serve as an exit candidate
- `relay_capable`: whether the node is expected to serve as a relay/entry candidate
- `rustynet_src_dir`: last-known Rustynet checkout path used by bootstrap-phase helpers
- `network_group`: inventory-backed underlay grouping for same-network validation
- `controller`: optional local lifecycle controller
  - current supported value: `{"type":"local_utm", ...}`
  - omit `controller` for VMs that are reachable over SSH but not hosted on this Mac

Operational meaning:

- `ops vm-lab-start` only works for entries with a local `controller`
- `ops vm-lab-stop` and `ops vm-lab-restart` can stop/restart those local-controller VMs
- `ops vm-lab-restart --wait-ready` is the preferred recovery path when UTM discovery still shows live IPs but `ready=false` or `ssh_port_status=closed`; it now waits for process presence, live IP resolution, SSH port-open state, and SSH auth readiness before returning
- `ops vm-lab-sync-repo`, `ops vm-lab-run`, and `ops vm-lab-bootstrap` work for any inventory entry with a valid `ssh_target`
- remote SSH-backed `ops vm-lab-*` commands now accept explicit `--ssh-identity-file` and `--known-hosts-file` inputs so the lab fleet can be driven reproducibly even when the operator key is not wired through ambient `~/.ssh/config`
- `ops vm-lab-sync-bootstrap` combines repo sync plus bootstrap/run across a selected VM set
- `ops vm-lab-bootstrap-phase` provides Rustynet-specific idempotent phases:
  `sync-source`, `build-release`, `install-release`, `restart-runtime`, `verify-runtime`, or `all`
- `ops vm-lab-check-known-hosts` verifies pinned host-key coverage for selected targets
- `ops vm-lab-preflight` validates SSH reachability, sudo, free disk, and required commands
- `ops vm-lab-status` captures per-node `rustynet status`, `netcheck`, service state, and handshake context
- `ops vm-lab-collect-artifacts` pulls a local per-node diagnostic bundle for later debugging
- `ops vm-lab-write-topology` renders a role-aware suite topology from the inventory metadata
- `ops vm-lab-issue-and-distribute-state` issues signed assignment/traversal state on an authority VM and installs it onto the selected topology nodes
- `ops vm-lab-run-suite` wraps the existing hardened live/cross-network lab scripts using inventory/topology metadata
- `ops vm-lab-write-live-lab-profile` renders a non-interactive profile for `scripts/e2e/live_linux_lab_orchestrator.sh`
- `ops vm-lab-setup-live-lab` is the setup-phase operator wrapper:
  - generates or validates the live-lab profile
  - runs the setup-only orchestration path through baseline validation
  - emits structured JSON with report-dir, stage outcomes, warnings, and next actions
  - supports `--resume-from` and `--rerun-stage` for setup-stage recovery in the same report dir
- `ops vm-lab-iterate-live-lab` is the narrow reduced-live-lab iteration wrapper:
  - runs only typed local validation steps (`fmt`, `check`, `check-bin`, `test`, `test-bin`)
  - writes the live-lab profile
  - launches the reduced live-lab orchestrator
  - waits for completion and prints the first failed stage plus key report/log paths
  - supports explicit provenance guards:
    - `--require-clean-tree`
    - `--require-local-head`
  - does **not** accept arbitrary shell commands
- `ops vm-lab-validate-live-lab-profile` validates a generated live-lab profile and can assert expected backend/source-mode plus five-node topology completeness
- `ops vm-lab-diagnose-live-lab-failure` reads a report/profile pair, captures `vm-lab-status`, and optionally collects the standard per-node artifact bundle for the configured live-lab targets
- `ops vm-lab-diff-live-lab-runs` compares two live-lab report directories and prints the first divergent stage plus changed stage outcomes
- `ops vm-lab-run-live-lab` launches the full live-lab suite from a generated profile, validates required run artifacts, and can continue from a setup-only report directory without rerunning setup
- remote or same-network VMs hosted on another machine should be recorded as SSH-reachable entries without a `controller`
- if you keep a bootstrap password in inventory, treat it as sensitive recovery metadata and do not log it or echo it in helper output
- if you keep a recovery-only host in inventory, set `include_in_all=false` so bulk lab selection does not treat it as a UTM lab member
- `network_group` is optional metadata for same-network validation; if you use `--require-same-network`, every selected inventory-backed node must declare the same `network_group`
- suite runners that claim cross-network behavior require distinct `network_group` / `last_known_network` values for the relevant suite roles; same-network metadata is not silently treated as cross-network proof

Example remote-only inventory entry:

```json
{
  "alias": "remote-debian-1",
  "ssh_target": "debian@192.168.0.55",
  "ssh_user": "debian",
  "node_id": "remote-client-1",
  "lab_role": "client",
  "mesh_ip": "100.64.10.55",
  "rustynet_src_dir": "/home/debian/Rustynet"
}
```

Example usage:

```bash
cargo run -q -p rustynet-cli -- \
  ops vm-lab-sync-repo \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --vm remote-debian-1 \
  --ssh-identity-file ~/.ssh/rustynet_lab_ed25519 \
  --known-hosts-file ~/.ssh/known_hosts \
  --repo-url git@github.com:iwanteague/Rustyfin.git \
  --dest-dir /home/debian/Rustyfin \
  --branch main

cargo run -q -p rustynet-cli -- \
  ops vm-lab-run \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --vm remote-debian-1 \
  --workdir /home/debian/Rustyfin \
  --program cargo \
  --arg build \
  --arg --release

cargo run -q -p rustynet-cli -- \
  ops vm-lab-sync-bootstrap \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --all \
  --require-same-network \
  --repo-url git@github.com:iwanteague/Rustyfin.git \
  --dest-dir /home/debian/Rustyfin \
  --program cargo \
  --arg build \
  --arg --release

cargo run -q -p rustynet-cli -- \
  ops vm-lab-write-live-lab-profile \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --output profiles/live_lab/generated_vm_lab.env \
  --ssh-identity-file ~/.ssh/rustynet_lab_ed25519 \
  --ssh-known-hosts-file ~/.ssh/known_hosts \
  --exit-vm debian-headless-1 \
  --client-vm debian-headless-2 \
  --entry-vm debian-headless-3 \
  --aux-vm debian-headless-4 \
  --extra-vm debian-headless-5 \
  --require-same-network

cargo run -q -p rustynet-cli -- \
  ops vm-lab-validate-live-lab-profile \
  --profile profiles/live_lab/generated_vm_lab.env \
  --expected-backend linux-wireguard-userspace-shared \
  --expected-source-mode local-head \
  --require-five-node

cargo run -q -p rustynet-cli -- \
  ops vm-lab-setup-live-lab \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --report-dir artifacts/live_lab/setup_example \
  --ssh-identity-file ~/.ssh/rustynet_lab_ed25519 \
  --known-hosts-file ~/.ssh/known_hosts \
  --exit-vm debian-headless-1 \
  --client-vm debian-headless-2 \
  --entry-vm debian-headless-3 \
  --aux-vm debian-headless-4 \
  --extra-vm debian-headless-5 \
  --require-same-network

cargo run -q -p rustynet-cli -- \
  ops vm-lab-iterate-live-lab \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --ssh-identity-file ~/.ssh/rustynet_lab_ed25519 \
  --ssh-known-hosts-file ~/.ssh/known_hosts \
  --exit-vm debian-headless-1 \
  --client-vm debian-headless-2 \
  --entry-vm debian-headless-3 \
  --aux-vm debian-headless-4 \
  --extra-vm debian-headless-5 \
  --require-same-network \
  --backend linux-wireguard-userspace-shared \
  --require-clean-tree \
  --require-local-head \
  --validation-step fmt \
  --validation-step check:rustynet-cli \
  --validation-step test-bin:rustynet-cli:live_linux_lan_toggle_test \
  --collect-failure-diagnostics

cargo run -q -p rustynet-cli -- \
  ops vm-lab-run-live-lab \
  --profile artifacts/live_lab/setup_example/setup_profile.env \
  --report-dir artifacts/live_lab/setup_example \
  --skip-cross-network

cargo run -q -p rustynet-cli -- \
  ops vm-lab-diagnose-live-lab-failure \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --profile artifacts/live_lab/setup_example/setup_profile.env \
  --report-dir artifacts/live_lab/setup_example \
  --collect-artifacts

cargo run -q -p rustynet-cli -- \
  ops vm-lab-diff-live-lab-runs \
  --old-report-dir artifacts/live_lab/iteration_122 \
  --new-report-dir artifacts/live_lab/iteration_123

cargo run -q -p rustynet-cli -- \
  ops vm-lab-run-live-lab \
  --profile profiles/live_lab/generated_vm_lab.env \
  --dry-run

cargo run -q -p rustynet-cli -- \
  ops vm-lab-preflight \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --all \
  --ssh-identity-file ~/.ssh/rustynet_lab_ed25519 \
  --known-hosts-file ~/.ssh/known_hosts \
  --require-command git \
  --require-command cargo \
  --require-rustynet-installed

cargo run -q -p rustynet-cli -- \
  ops vm-lab-write-topology \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --suite full-live-lab \
  --output profiles/live_lab/generated_vm_lab_topology.json \
  --all \
  --require-same-network

cargo run -q -p rustynet-cli -- \
  ops vm-lab-bootstrap-phase \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --phase all \
  --ssh-identity-file ~/.ssh/rustynet_lab_ed25519 \
  --known-hosts-file ~/.ssh/known_hosts \
  --repo-url git@github.com:iwanteague/Rustynet.git \
  --dest-dir /home/debian/Rustynet \
  --all \
  --require-same-network

cargo run -q -p rustynet-cli -- \
  ops vm-lab-run-suite \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --suite full-live-lab \
  --ssh-identity-file ~/.ssh/rustynet_lab_ed25519 \
  --all \
  --dry-run
```

## Virtual Machines

### Parent Device Context For All Entries

- Parent device: `iwan’s MacBook Pro`
- Parent last known network IP: `192.168.0.20/24`
- Parent last known SSID: `unknown/unavailable from local unprivileged query`

### VM 1

- Display name: `debian-headless-1`
- Bundle path:
  `/Users/iwan/Library/Containers/com.utmapp.UTM/Data/Documents/debian-headless-1.utm`
- UTM UUID: `40F90934-537F-484D-B9CC-D8012202DE0F`
- Guest OS family: `Debian/Linux`
- Backend: `QEMU`
- Architecture: `aarch64`
- Memory: `2048 MB`
- Network adapters:
  - Shared NIC MAC: `3E:AE:A9:5A:61:82`
- Last-known guest IP: `192.168.64.3`
- Live IPs from UTM query:
  - `192.168.64.3`
  - `fd21:69d4:6afd:fa50:3cae:a9ff:fe5a:6182`
  - `fd21:69d4:6afd:fa50:9a08:e072:9844:b7ad`
  - `fe80::6023:d956:36c2:c94e`
- Last-known IP confidence: `live-confirmed via UTM query ip on 2026-04-07T16:20:45Z`
- Suggested Rustynet node ID: `exit-1`
- Suggested lab role: `exit`
- Suggested mesh IP: `100.64.0.1`
- SSH operator key: `~/.ssh/rustynet_lab_ed25519`
- Suggested connect template:
  `ssh -i ~/.ssh/rustynet_lab_ed25519 debian@192.168.64.3`

### VM 2

- Display name: `debian-headless-2`
- Bundle path:
  `/Users/iwan/Library/Containers/com.utmapp.UTM/Data/Documents/debian-headless-2.utm`
- UTM UUID: `7BD5A6C3-4138-4394-936A-A61F6A4480AE`
- Guest OS family: `Debian/Linux`
- Backend: `QEMU`
- Architecture: `aarch64`
- Memory: `2048 MB`
- Network adapters:
  - Shared NIC MAC: `3E:AE:A9:5A:61:82`
- Last-known guest IP: `192.168.64.4`
- Live IPs from UTM query:
  - `192.168.64.4`
  - `fd21:69d4:6afd:fa50:4344:bf8a:e4ff:3154`
  - `fe80::a419:949:1c4a:4d9f`
- Last-known IP confidence: `live-confirmed via UTM query ip on 2026-04-07T16:20:45Z`
- Suggested Rustynet node ID: `client-1`
- Suggested lab role: `client`
- Suggested mesh IP: `100.64.0.2`
- SSH operator key: `~/.ssh/rustynet_lab_ed25519`
- Suggested connect template:
  `ssh -i ~/.ssh/rustynet_lab_ed25519 debian@192.168.64.4`

### VM 3

- Display name: `debian-headless-3`
- Bundle path:
  `/Users/iwan/Library/Containers/com.utmapp.UTM/Data/Documents/debian-headless-3.utm`
- UTM UUID: `58123566-1DAC-4B6F-8BA3-A6BFB561B439`
- Guest OS family: `Debian/Linux`
- Backend: `QEMU`
- Architecture: `aarch64`
- Memory: `2048 MB`
- Network adapters:
  - Shared NIC MAC: `3E:AE:A9:5A:61:82`
- Last-known guest IP: `192.168.64.5`
- Live IPs from UTM query:
  - `192.168.64.5`
  - `fd21:69d4:6afd:fa50:6259:ad04:5665:deda`
  - `fe80::bec8:79f7:a83d:ddc`
- Last-known IP confidence: `live-confirmed via UTM query ip on 2026-04-07T16:20:45Z`
- Suggested Rustynet node ID: `relay-1`
- Suggested lab role: `relay`
- Suggested mesh IP: `100.64.0.3`
- SSH operator key: `~/.ssh/rustynet_lab_ed25519`
- Suggested connect template:
  `ssh -i ~/.ssh/rustynet_lab_ed25519 debian@192.168.64.5`

### VM 4

- Display name: `debian-headless-4`
- Bundle path:
  `/Users/iwan/Library/Containers/com.utmapp.UTM/Data/Documents/debian-headless-4.utm`
- UTM UUID: `80C0AC91-4384-4FB0-A44F-3F3E94892F28`
- Guest OS family: `Debian/Linux`
- Backend: `QEMU`
- Architecture: `aarch64`
- Memory: `2048 MB`
- Network adapters:
  - Shared NIC MAC: `3E:AE:A9:5A:61:82`
- Last-known guest IP: `192.168.64.6`
- Live IPs from UTM query:
  - `192.168.64.6`
  - `fd21:69d4:6afd:fa50:dc8c:2918:43ca:d40d`
  - `fe80::cadd:6589:4e14:8590`
- Last-known IP confidence: `live-confirmed via UTM query ip on 2026-04-07T16:20:45Z`
- Suggested Rustynet node ID: `aux-1`
- Suggested lab role: `aux`
- Suggested mesh IP: `100.64.0.4`
- SSH operator key: `~/.ssh/rustynet_lab_ed25519`
- Suggested connect template:
  `ssh -i ~/.ssh/rustynet_lab_ed25519 debian@192.168.64.6`

### VM 5

- Display name: `debian-headless-5`
- Bundle path:
  `/Users/iwan/Library/Containers/com.utmapp.UTM/Data/Documents/debian-headless-5.utm`
- UTM UUID: `72E7F328-6080-4A22-80A7-F601DCA592B0`
- Guest OS family: `Debian/Linux`
- Backend: `QEMU`
- Architecture: `aarch64`
- Memory: `2048 MB`
- Network adapters:
  - Shared NIC MAC: `3E:AE:A9:5A:61:82`
- Last-known guest IP: `192.168.64.7`
- Live IPs from UTM query:
  - `192.168.64.7`
  - `fd21:69d4:6afd:fa50:f0c2:96e5:4c55:6a59`
  - `fe80::a42a:e764:39c7:4f33`
- Last-known IP confidence: `live-confirmed via UTM query ip on 2026-04-07T16:20:45Z`
- Suggested Rustynet node ID: `extra-1`
- Suggested lab role: `extra`
- Suggested mesh IP: `100.64.0.5`
- SSH operator key: `~/.ssh/rustynet_lab_ed25519`
- Suggested connect template:
  `ssh -i ~/.ssh/rustynet_lab_ed25519 debian@192.168.64.7`

### VM 6

- Display name: `Windows`
- Inventory alias: `windows-utm-1`
- Bundle path:
  `/Users/iwan/Library/Containers/com.utmapp.UTM/Data/Documents/Windows.utm`
- UTM UUID: `2CAECCF7-92FF-44E8-99B6-18C0FC9D9235`
- Guest OS family: `Windows 11`
- Backend: `QEMU`
- Last-known guest IP: `192.168.64.14`
- Last-known network: `utm-shared-192.168.64.0/24`
- Inventory network group: `utm-shared-192.168.64.0/24`
- Inventory lab role: `windows_client`
- Inventory platform metadata:
  - `platform=windows`
  - `remote_shell=powershell`
  - `guest_exec_mode=windows_powershell`
  - `service_manager=windows_service`
- Last-known Rustynet source dir: `C:\Rustynet`
- Inventory SSH user: `Administrator`
- Inventory SSH target: `192.168.64.14`
- Operator note:
  this guest is tracked for Windows bootstrap/service validation and optional
  `--windows-vm` sidecar orchestration, not as one of the five Linux live-lab
  nodes.

## Historical IP Evidence Used In This Pass

Current live guest IPs from UTM `query ip`:

- `192.168.64.3`
- `192.168.64.4`
- `192.168.64.5`
- `192.168.64.6`
- `192.168.64.7`
- `192.168.64.14`

Historical UTM-style guest IPs retained from older host-key history:

- `192.168.64.18`
- `192.168.64.22`
- `192.168.64.24`
- `192.168.64.26`
- `192.168.64.28`
- `192.168.64.29`

Interpretation:
- `192.168.64.3`, `192.168.64.4`, `192.168.64.5`, `192.168.64.6`, `192.168.64.7`, and `192.168.64.14` are the current tracked local-UTM guest IPv4 addresses confirmed by repo evidence.
- `192.168.64.22`, `192.168.64.24`, `192.168.64.26`, `192.168.64.28`, and `192.168.64.29` are stale historical snapshot addresses and should not be used for current lab runs.
- `192.168.64.18` remains an unmatched historical UTM-style guest address from SSH host-key history.

## Recommended Next Steps

1. Refresh this inventory whenever the UTM live query output changes, the VMs are reimaged, or the Windows validation guest is rebuilt.
2. If the Debian login user changes from `debian`, update the connect templates and lab profiles accordingly.
3. If desired, create a dedicated SSH config stanza per VM using the existing lab key.
4. If desired, generate a fresh dedicated keypair for this UTM VM set and update this inventory with:
   - private key path
   - public key path
   - fingerprint
   - rollout status inside each VM’s `authorized_keys`
