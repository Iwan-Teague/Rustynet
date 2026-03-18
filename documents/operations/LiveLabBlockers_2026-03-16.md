# Live Lab Blockers 2026-03-16

## Scope

Fresh-install live-lab execution against the current working tree on:

- `debian@192.168.18.49`
- `debian@192.168.18.65`
- `ubuntu@192.168.18.52`
- `fedora@192.168.18.51`
- `mint@192.168.18.53`

## Findings

### 1. `192.168.18.49` is not reachable on the underlay LAN

This is a lab/VM availability failure, not a RustyNet overlay failure.

Evidence:

- Five-node run failed in `prime_remote_access` on `.49`:
  - [failure_digest.md](/Users/iwanteague/Desktop/Rustynet/artifacts/live_lab/20260316T162709Z/failure_digest.md)
- Direct SSH transport debug from the operator machine timed out:
  - `ssh ... debian@192.168.18.49`
  - result: `connect to address 192.168.18.49 port 22: Operation timed out`
- Probe from the healthy Debian `.65` host showed `.49` is not reachable on the same LAN:
  - `ping`: `100% packet loss`
  - `nc`: `No route to host`
  - `ip neigh`: `192.168.18.49 dev enp0s8 FAILED`

Impact:

- `.49` cannot currently serve as the exit node in the five-node lab.

Required VM-side fix:

1. Recover the VM and its virtual NIC at the hypervisor or console level.
2. Confirm plain underlay reachability before any RustyNet run:
   - SSH reachable on port `22`
   - responds to LAN ping from another VM

### 2. `debian@192.168.18.65` initially lacked `sudo`, and is now also unstable on the underlay LAN

This is a host-account provisioning failure, not a RustyNet runtime failure.

Initial evidence:

- Direct remote sudo validation on `.65` returned:
  - `debian is not in the sudoers file.`
  - `sudo validation failed for user debian`
  - `groups: debian users`
- Revalidated through the orchestrator after tightening the remote sudo preflight:
  - [failure_digest.md](/Users/iwanteague/Desktop/Rustynet/artifacts/live_lab/20260316T165145Z/failure_digest.md)
  - [prime_remote_access.log](/Users/iwanteague/Desktop/Rustynet/artifacts/live_lab/20260316T165145Z/logs/prime_remote_access.log)

Current evidence after the VM-side sudo change:

- Fresh four-node run still failed in `prime_remote_access` on `.65`:
  - [failure_digest.md](/Users/iwanteague/Desktop/Rustynet/artifacts/live_lab/20260316T170048Z/failure_digest.md)
- Direct operator probe now reports:
  - `nc`: `Host is down`
- Probe from healthy Ubuntu `.52` shows `.65` is not stably reachable on the LAN:
  - `ping`: `100% packet loss`
  - `nc`: timed out on port `22`
  - `ip neigh`: `INCOMPLETE`

Impact:

- `.65` cannot currently participate in fresh-install runs.
- The sudo provisioning problem was real and correctly surfaced, but the current blocker is broader host availability on the VM/LAN itself.

Required VM-side fix:

1. Ensure `debian` is in the appropriate admin group on the VM, typically:
   - `sudo usermod -aG sudo debian`
2. Re-login or reboot the VM so the new group membership takes effect.
3. Confirm:
   - `id -Gn` includes `sudo`
   - `sudo -v` succeeds for `debian`
4. Confirm plain underlay reachability before any RustyNet run:
   - SSH on port `22`
   - responds to LAN probes from another healthy VM

### 3. `ubuntu@192.168.18.52` has broken local hostname resolution, which causes `sudo` verification to fail

This is a VM/guest OS configuration defect, not a RustyNet overlay failure.

Evidence:

- The four-node run now fails cleanly in `prime_remote_access` only on `.52`:
  - [failure_digest.md](/Users/iwanteague/Desktop/Rustynet/artifacts/live_lab/20260316T175021Z/failure_digest.md)
- The helper now surfaces the failing account context:
  - `sudo validation failed for user ubuntu`
  - `groups: ubuntu sudo`
- Direct guest inspection shows the hostname is not mapped in `/etc/hosts`:
  - `/etc/hostname`: `ubuntu`
  - `/etc/hosts`: no `ubuntu` entry
- Direct resolution probe hangs:
  - `getent hosts $(hostname)` on `.52` does not return

Impact:

- `prime_remote_access` cannot complete on `.52`.
- The four-node lab cannot proceed until the guest can resolve its own hostname locally.

Required VM-side fix:

1. On the `.52` VM console, add a loopback hostname mapping:
   - `echo '127.0.1.1 ubuntu' | sudo tee -a /etc/hosts`
2. Confirm local resolution before rerunning the lab:
   - `getent hosts $(hostname)`
3. Confirm `sudo -v` succeeds normally for `ubuntu`.

## Repo-side fixes completed

### Orchestrator robustness

- [live_linux_lab_orchestrator.sh](/Users/iwanteague/Desktop/Rustynet/scripts/e2e/live_linux_lab_orchestrator.sh)
  - fixed explicit profile loading so a CLI override does not abort startup under `set -e`
  - bounded cleanup/system commands with explicit timeouts

### Remote sudo preflight hardening

- [live_lab_common.sh](/Users/iwanteague/Desktop/Rustynet/scripts/e2e/live_lab_common.sh)
  - `prime_remote_access` now verifies remote `sudo` immediately after pushing `/tmp/rn_sudo.pass`
  - failures now surface before cleanup/bootstrap
  - worker logs now include user/group context for sudo failures
  - the shared root path now repushes the temporary sudo credential before each privileged remote action
  - the shared verifier now bounds `sudo` verification instead of hanging forever
  - the verifier now checks local hostname mapping first so guest-OS hostname defects surface explicitly

### Guest bootstrap repair

- [live_linux_lab_orchestrator.sh](/Users/iwanteague/Desktop/Rustynet/scripts/e2e/live_linux_lab_orchestrator.sh)
  - the generated bootstrap path now repairs a missing loopback hostname mapping once it is running as root, preventing the same `/etc/hosts` defect from surviving later bootstrap on newly provisioned Debian-like guests

## Next action

After the VM-side fixes above:

1. rerun the four-node fresh-install live suite on:
   - `debian@192.168.18.65`
   - `ubuntu@192.168.18.52`
   - `fedora@192.168.18.51`
   - `mint@192.168.18.53`
2. continue from the first real RustyNet runtime or gate failure, if any
