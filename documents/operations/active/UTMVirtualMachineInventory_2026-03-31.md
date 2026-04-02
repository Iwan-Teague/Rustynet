# UTM Virtual Machine Inventory

Last updated:
`2026-03-31T17:13:34Z`

Repository root:
`/Users/iwanteague/Desktop/Rustynet`

Purpose:
- keep a last-known local record of the UTM Debian headless lab VMs on this Mac,
- record parent-device context,
- record current SSH operator key material by path and fingerprint,
- avoid storing private key contents in the document.
- provide a human-readable companion to the machine-readable inventory at
  `/Users/iwanteague/Desktop/Rustynet/documents/operations/active/vm_lab_inventory.json`
  used by `rustynet-cli ops vm-lab-*`.

## Parent Device

- Parent device: `iwan’s MacBook Air`
- Local host name: `iwans-MacBook-Air`
- Hostname: `Mac`
- OS: `macOS 26.3.1 (a)` build `25D771280a`
- Architecture: `arm64`
- Active parent interface at time of capture: `en0`
- Last known parent IP on active interface: `192.168.0.20/24`
- Last known parent network SSID: unavailable from non-privileged local queries on this host
- UTM bundle root:
  `/Users/iwanteague/Library/Containers/com.utmapp.UTM/Data/Documents`

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
- This pass did not generate a new private key because an existing dedicated lab key is already present on the host.
- If you want a fresh per-lab or per-VM keypair, generate it separately and update this inventory with the new path and fingerprint.

## Inventory Notes

- All five VMs are UTM `QEMU` guests.
- All five are configured as `aarch64` Debian/Linux guests with `2048 MB` memory.
- All five currently have two NICs:
  - NIC 0: `Mode=Shared`
  - NIC 1: `Mode=Host`
- No live guest-agent or live SSH reachability verification was performed in this pass.
- The per-VM last-known IPs below are **inferred** from local `~/.ssh/known_hosts.old` history and UTM naming/order, not live-confirmed from inside the guests.
- One extra UTM-style historical IP, `192.168.64.18`, exists in `known_hosts.old` but could not be confidently tied to one of the five current VM bundles during this pass.

## Machine-Readable Inventory Model

The companion inventory file at
`/Users/iwanteague/Desktop/Rustynet/documents/operations/active/vm_lab_inventory.json`
is now the operator-facing source for `rustynet-cli ops vm-lab-*`.

Entry model:

- `alias`: stable operator label such as `debian-headless-1`
- `ssh_target`: SSH alias, hostname, or `user@host` target that is reachable from this Mac
- `ssh_user`: optional default SSH username override
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
- `ops vm-lab-sync-repo`, `ops vm-lab-run`, and `ops vm-lab-bootstrap` work for any inventory entry with a valid `ssh_target`
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
- `ops vm-lab-run-live-lab` launches the existing live-lab orchestrator from a generated profile
- remote or same-network VMs hosted on another machine should be recorded as SSH-reachable entries without a `controller`
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
  --ssh-identity-file /Users/iwanteague/.ssh/rustynet_lab_ed25519 \
  --ssh-known-hosts-file /Users/iwanteague/.ssh/known_hosts \
  --exit-vm debian-headless-1 \
  --client-vm debian-headless-2 \
  --entry-vm debian-headless-3 \
  --aux-vm debian-headless-4 \
  --extra-vm debian-headless-5 \
  --require-same-network

cargo run -q -p rustynet-cli -- \
  ops vm-lab-run-live-lab \
  --profile profiles/live_lab/generated_vm_lab.env \
  --dry-run

cargo run -q -p rustynet-cli -- \
  ops vm-lab-preflight \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --all \
  --known-hosts-file /Users/iwanteague/.ssh/known_hosts \
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
  --repo-url git@github.com:iwanteague/Rustynet.git \
  --dest-dir /home/debian/Rustynet \
  --all \
  --require-same-network

cargo run -q -p rustynet-cli -- \
  ops vm-lab-run-suite \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --suite full-live-lab \
  --ssh-identity-file /Users/iwanteague/.ssh/rustynet_lab_ed25519 \
  --all \
  --dry-run
```

## Virtual Machines

### Parent Device Context For All Entries

- Parent device: `iwan’s MacBook Air`
- Parent last known network IP: `192.168.0.20/24`
- Parent last known SSID: `unknown/unavailable from local unprivileged query`

### VM 1

- Display name: `debian headless 1`
- Bundle path:
  `/Users/iwanteague/Library/Containers/com.utmapp.UTM/Data/Documents/debian headless 1.utm`
- UTM UUID: `40F90934-537F-484D-B9CC-D8012202DE0F`
- Guest OS family: `Debian/Linux`
- Backend: `QEMU`
- Architecture: `aarch64`
- Memory: `2048 MB`
- Network adapters:
  - Shared NIC MAC: `86:73:E8:2E:A6:BE`
  - Host NIC MAC: `02:64:00:00:00:22`
- Last-known guest IP: `192.168.64.22`
- Last-known IP confidence: `inferred from historical SSH host-key sequence`
- Suggested Rustynet node ID: `exit-1`
- Suggested lab role: `exit`
- Suggested mesh IP: `100.64.0.1`
- SSH operator key: `~/.ssh/rustynet_lab_ed25519`
- Suggested connect template:
  `ssh -i ~/.ssh/rustynet_lab_ed25519 <vm-user>@192.168.64.22`

### VM 2

- Display name: `debian headless 2`
- Bundle path:
  `/Users/iwanteague/Library/Containers/com.utmapp.UTM/Data/Documents/debian headless 2.utm`
- UTM UUID: `7BD5A6C3-4138-4394-936A-A61F6A4480AE`
- Guest OS family: `Debian/Linux`
- Backend: `QEMU`
- Architecture: `aarch64`
- Memory: `2048 MB`
- Network adapters:
  - Shared NIC MAC: `12:9B:9F:C5:73:F5`
  - Host NIC MAC: `02:64:00:00:00:24`
- Last-known guest IP: `192.168.64.24`
- Last-known IP confidence: `inferred from historical SSH host-key sequence`
- Suggested Rustynet node ID: `client-1`
- Suggested lab role: `client`
- Suggested mesh IP: `100.64.0.2`
- SSH operator key: `~/.ssh/rustynet_lab_ed25519`
- Suggested connect template:
  `ssh -i ~/.ssh/rustynet_lab_ed25519 <vm-user>@192.168.64.24`

### VM 3

- Display name: `debian headless 3`
- Bundle path:
  `/Users/iwanteague/Library/Containers/com.utmapp.UTM/Data/Documents/debian headless 3.utm`
- UTM UUID: `58123566-1DAC-4B6F-8BA3-A6BFB561B439`
- Guest OS family: `Debian/Linux`
- Backend: `QEMU`
- Architecture: `aarch64`
- Memory: `2048 MB`
- Network adapters:
  - Shared NIC MAC: `72:F5:0A:38:C7:89`
  - Host NIC MAC: `02:64:00:00:00:26`
- Last-known guest IP: `192.168.64.26`
- Last-known IP confidence: `inferred from historical SSH host-key sequence`
- Suggested Rustynet node ID: `relay-1`
- Suggested lab role: `relay`
- Suggested mesh IP: `100.64.0.3`
- SSH operator key: `~/.ssh/rustynet_lab_ed25519`
- Suggested connect template:
  `ssh -i ~/.ssh/rustynet_lab_ed25519 <vm-user>@192.168.64.26`

### VM 4

- Display name: `headless debian 4`
- Bundle path:
  `/Users/iwanteague/Library/Containers/com.utmapp.UTM/Data/Documents/headless debian 4.utm`
- UTM UUID: `80C0AC91-4384-4FB0-A44F-3F3E94892F28`
- Guest OS family: `Debian/Linux`
- Backend: `QEMU`
- Architecture: `aarch64`
- Memory: `2048 MB`
- Network adapters:
  - Shared NIC MAC: `BA:23:29:BE:FA:33`
  - Host NIC MAC: `02:64:00:00:00:28`
- Last-known guest IP: `192.168.64.28`
- Last-known IP confidence: `inferred from historical SSH host-key sequence`
- Suggested Rustynet node ID: `aux-1`
- Suggested lab role: `aux`
- Suggested mesh IP: `100.64.0.4`
- SSH operator key: `~/.ssh/rustynet_lab_ed25519`
- Suggested connect template:
  `ssh -i ~/.ssh/rustynet_lab_ed25519 <vm-user>@192.168.64.28`

### VM 5

- Display name: `headless debian 5`
- Bundle path:
  `/Users/iwanteague/Library/Containers/com.utmapp.UTM/Data/Documents/headless debian 5.utm`
- UTM UUID: `72E7F328-6080-4A22-80A7-F601DCA592B0`
- Guest OS family: `Debian/Linux`
- Backend: `QEMU`
- Architecture: `aarch64`
- Memory: `2048 MB`
- Network adapters:
  - Shared NIC MAC: `BA:23:29:BE:FA:35`
  - Host NIC MAC: `02:64:00:00:00:30`
- Last-known guest IP: `192.168.64.29`
- Last-known IP confidence: `inferred from historical SSH host-key sequence`
- Suggested Rustynet node ID: `extra-1`
- Suggested lab role: `extra`
- Suggested mesh IP: `100.64.0.5`
- SSH operator key: `~/.ssh/rustynet_lab_ed25519`
- Suggested connect template:
  `ssh -i ~/.ssh/rustynet_lab_ed25519 <vm-user>@192.168.64.29`

## Historical IP Evidence Used In This Pass

Observed UTM-style guest IPs in `~/.ssh/known_hosts.old`:

- `192.168.64.18`
- `192.168.64.22`
- `192.168.64.24`
- `192.168.64.26`
- `192.168.64.28`
- `192.168.64.29`

Interpretation:
- `192.168.64.22`, `192.168.64.24`, `192.168.64.26`, `192.168.64.28`, and `192.168.64.29` are the currently observed shared-network guest addresses inferred from the live ARP table and the recorded per-VM NIC MAC addresses.
- `192.168.64.18` remains an unmatched historical UTM-style guest address from SSH host-key history.

## Recommended Next Steps

1. Live-verify each guest from the UTM console or by SSH while the VM is running.
2. Confirm the actual guest username for each Debian VM and replace `<vm-user>` in the templates.
3. If desired, create a dedicated SSH config stanza per VM using the existing lab key.
4. If desired, generate a fresh dedicated keypair for this UTM VM set and update this inventory with:
   - private key path
   - public key path
   - fingerprint
   - rollout status inside each VM’s `authorized_keys`
