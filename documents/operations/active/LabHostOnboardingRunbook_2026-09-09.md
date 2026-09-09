# Lab host onboarding runbook — 2026-09-09

How a new machine becomes a `--node` live-lab HOST (a box that holds guests and
can drive runs itself), driven through the existing `ops vm-lab-*` commands and
the `rustynet-mcp-lab-state` tools. Written from the two hosts onboarded this
week: `lenovo-bot` (Ubuntu, x86-64, LAN 192.168.0.0/24) and `katana` (Debian 13
laptop, tailnet name `debian`, 100.122.143.29, Wi-Fi 192.168.18.0/24). Every
step below has a command and the failure it prevents; the three marked
**(bit us)** each cost a failed launch on 2026-09-09.

## 0) What "onboarded" means

| Level | Meaning | Proof |
|---|---|---|
| Host reachable | SSH from the driving Mac with a key, no password | `ssh -o BatchMode=yes user@host hostname` |
| Host discoverable | `hosts[]` entry in `vm_lab_inventory.json`; libvirt answers | `discover_hosts` → `probe=ok (QEMU x.y)` |
| Host pinned | its checkout is on the commit the Mac is on | `sync_host` / `host_preflight` gates 2–6 |
| Host can drive | it can run `ops vm-lab-orchestrate-live-lab` on its own guests | `launch_live_lab_on_host` + a run row |
| Guests ready | ≥1 registered guest running with an IP and the guest toolchain | `host_preflight` gate 7 `guests_ready`, `provision_guest_toolchain --verify-only` |

`katana` is at "host can drive, zero guests" — it needs base images (Debian
cloud image for Linux guests; a Windows 11 x64 ISO for the Windows cell).
`lenovo-bot` is fully onboarded (two Debian guests; run `livelab-1788919346`).

## 1) Host-side prerequisites (once per host, as the lab user)

```bash
# packages (Debian/Ubuntu)
sudo apt-get install -y clang llvm build-essential pkg-config libssl-dev libsqlite3-dev \
  nftables wireguard-tools tcpdump git libvirt-daemon-system qemu-system-x86 virtinst \
  cloud-image-utils genisoimage ovmf swtpm-tools sshpass
sudo usermod -aG libvirt,kvm "$USER"          # re-login afterwards
# pinned toolchain, NOT the distro's rustc
curl -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --profile minimal \
  --default-toolchain "$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)" -c rustfmt -c clippy
```

Three things the generic install does not do, each of which broke a launch **(bit us)**:

1. **cargo on the non-login PATH.** The host-run launcher is a detached
   non-login shell; `~/.profile` never runs. The launcher template now prepends
   `$HOME/.cargo/bin` itself (`014a7bd7`), but `sync_host`/ad-hoc ssh commands
   do not — link the shims: `sudo ln -sf ~/.cargo/bin/{cargo,rustc,rustup} /usr/local/bin/`.
2. **umask 022.** Debian/Ubuntu default `0002` makes every `git reset --hard`
   re-create `Cargo.toml` as 664, and the orchestrator refuses a group-writable
   workspace root (fail-closed check). Put `umask 022` in `~/.profile` AND
   `~/.bashrc`, and run `chmod -R go-w ~/Rustynet` once after cloning.
3. **an SSH key on the host.** A host that drives its own guests needs its own
   `~/.ssh/id_ed25519` (the guests only trusted the Mac's key until it was
   added): `ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519`, append its
   `.pub` to each guest's `authorized_keys`, and pin the guests' host keys
   (`ssh-keyscan -t ed25519 <guest-ip> >> ~/.ssh/known_hosts`). The
   orchestrator uses `StrictHostKeyChecking=yes`; an unpinned guest fails closed.

Clone the public repo (`git clone https://github.com/Iwan-Teague/Rustynet.git
~/Rustynet`) — the host reads its own checkout for run provenance, so it must be
a real clone, not a copy. libvirt: `virsh -c qemu:///system pool-define-as
default dir --target /var/lib/libvirt/images && virsh pool-build default &&
virsh pool-start default && virsh pool-autostart default`; the `default` NAT
network normally exists already.

## 2) Register the host (from the Mac)

Add a `hosts[]` entry to `documents/operations/active/vm_lab_inventory.json`
(this is the one place a hand edit is correct — guest IPs are refreshed by
tooling, host entries are declared):

```json
{ "host_id": "katana", "kind": "libvirt",
  "connect_uri": "qemu+ssh://debian@192.168.18.44/system",
  "alt_ssh_endpoints": ["debian@100.122.143.29"],
  "guest_subnet": "192.168.122.0/24", "repo_dir": "/home/debian/Rustynet",
  "notes": "…hardware, LAN, virt capability, how it is reached…" }
```

Passwords never go in the inventory (public repo): `sshpass` priming reads the
untracked sidecar `vm_lab_inventory.secrets.json` (mode 600). Prime the LAB
key once — the tooling's default identity is `~/.ssh/rustynet_lab_ed25519`
(`default_lab_ssh_identity_path`), NOT `id_ed25519`; a host that only trusts
your personal key answers ad-hoc ssh but fails `host_preflight` gate 5 with
`Permission denied (publickey)` **(bit us)**:
`sshpass -p … ssh-copy-id -i ~/.ssh/rustynet_lab_ed25519.pub user@host`.
On a umask-002 host the Debian default `~/.profile` carries a commented
`#umask 022`, so a `grep -q "umask 022" || echo …` idempotency check matches
the comment and appends nothing — write the line unconditionally.

Then, in order (MCP tool → CLI equivalent):

| Step | Tool | Proves |
|---|---|---|
| 1 | `discover_hosts` (`ops vm-lab-discover-hosts --host katana`) | libvirt over `qemu+ssh` answers; lists domains |
| 2 | `sync_host` (`ops vm-lab-sync-host --host katana --commit <sha>`) | host checkout is on the pushed commit (refuses a dirty Mac tree; `--allow-dirty` records the divergence) |
| 3 | `host_preflight` (`ops vm-lab-host-preflight --hosts katana --commit <sha>`) | seven ordered gates; `GO` only with ready guests |

`sync_host` fetches from the public origin, so the commit must be pushed first.
After every `sync_host`/reset on a umask-002 host, re-run `chmod -R go-w`.

## 3) Guests

| Step | Tool | Notes |
|---|---|---|
| 1 | put a base image in the pool | Debian generic cloud image (`.qcow2`) for Linux guests; Windows 11 x64 ISO + `virtio-win.iso` for a Windows guest (owner supplies images; downloads need approval) |
| 2 | `provision_guest` (`ops vm-lab-provision-guest --host katana --image <file> --name <guest>`) | **dry_run first**; seeds cloud-init with the driving host's pubkey; `--cpu host-passthrough`, `--video vga` baked in |
| 3 | add the guest to `entries[]` (`alias`, `node_id`, `ssh_user`, `ssh_target`, `controller: {type: libvirt, domain, host_id}`) then `discover_hosts --update-inventory-live-ips` | never hand-edit live IPs |
| 4 | `provision_guest_toolchain --aliases <guest>` | apt set + pinned rustup + shims in `/usr/local/bin` (non-login ssh PATH) |
| 5 | `bootstrap_vm --alias <guest> --phase all` | sync-source → build → install → runtime smokes; slow, drive it from a shell |
| 6 | `host_preflight` → `GO` | then `launch_live_lab_on_host` with `--node <guest>:<role>` |

Windows guests: the host needs nested virt for WinNAT/exit
(`cat /sys/module/kvm_intel/parameters/nested` → `Y` on katana), `ovmf`,
`swtpm` (TPM 2.0 for Windows 11), and the guest is bootstrapped by
`scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1` over SSH.

## 4) Verification checklist before the first run on a host

```bash
ssh -o BatchMode=yes user@host 'bash -c "command -v cargo; umask; stat -c %a Rustynet/Cargo.toml; ls ~/.ssh/id_ed25519; git -C Rustynet rev-parse --short HEAD"'
```
Expected: a cargo path, `0022`, `644`, the key, the pushed commit. Then
`host_preflight` must print `VERDICT: GO`.

## 5) Cross-network note

`lenovo-bot` (192.168.0.0/24, guests bridged onto that LAN) and `katana`
(192.168.18.0/24 Wi-Fi, guests NAT'd on virbr0) are on different physical
LANs. Measured 2026-09-09 from the Mac (itself on 192.168.18.16): the two
LANs are ROUTED — `192.168.0.29` answers in ~110 ms and the bridged lenovo
guests (`192.168.0.30/.31`) are reachable, no tailnet involved (the Mac's
Tailscale client was stopped at the time). Katana's own guests sit behind its
virbr0 NAT, so a lenovo↔katana cross-network run needs them exposed through
the host (libvirt port-forward / a routed guest network on katana) — but no
Mac host-networking change (CP-1) is involved, which is why this pair replaces
the Mac-vmnet cross-network topology.
