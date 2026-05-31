#!/usr/bin/env bash
# probe_and_recover_local_utm.sh — discover every local UTM VM, probe its
# SSH reachability, and recover any Linux VM whose inbound SSH is being
# blocked by a stale rustynetd nftables killswitch from a prior lab run.
#
# WHEN TO USE
#   - retry-N's orchestrator-runs.log fails at `prime_remote_access` or
#     `cleanup_hosts` with TCP timeouts to one of the lab VMs.
#   - You changed VM networking (e.g., switched from UTM shared mode to
#     bridged) and the previous rustynet pf/nft killswitch is still loaded
#     inside the guest, dropping the SYN-ACK on TCP/22 because the source
#     IP is no longer in the prior management CIDR allowlist.
#   - You added a fresh VM and want a quick "is everything reachable"
#     baseline before launching an orchestrator run.
#
# WHAT IT DOES
#   1. Calls `cargo run --quiet --bin rustynet-cli -- ops
#      vm-lab-discover-local-utm` (JSON) to enumerate every registered UTM
#      VM, its DHCP-assigned IP, and its current SSH port status.
#   2. Prints a per-VM table: name, platform, live IP, SSH port status.
#   3. For each Linux VM whose SSH port is NOT open, uses `utmctl exec` to
#      invoke `sudo nft flush ruleset` and stop the rustynetd services
#      inside the guest. This path does NOT depend on SSH — it goes through
#      the qemu-guest-agent socket. The Windows VM (windows-utm-1) is ALSO a
#      QEMU guest with a working guest agent, so it is auto-recovered the same
#      way: stop the RustyNet service + restore the outbound firewall policy
#      (the killswitch lockout = firewall AllowInbound,BlockOutbound). Only
#      macOS guests still require manual recovery, because UTM's Apple
#      Virtualization backend exposes no `utmctl exec` (via serial console:
#      `launchctl bootout system/com.rustynet.daemon` + `pfctl -F all -d`).
#   4. Re-probes TCP/22 on every VM after recovery and prints a final
#      summary table.
#
# IDEMPOTENCE
#   - Re-running after success is safe: `nft flush ruleset` on an already-
#     empty ruleset is a no-op; `systemctl stop` on a stopped service
#     exits 0; the re-probe phase only reads state.
#
# COMPATIBILITY
#   - Written for bash 3.2 (what macOS ships at /bin/bash). Uses parallel
#     indexed arrays instead of associative arrays so the script runs the
#     same regardless of whether `env bash` resolves to bash 3.2 or a
#     newer homebrew bash.

set -euo pipefail

UTMCTL="${UTMCTL:-/Applications/UTM.app/Contents/MacOS/utmctl}"
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

if [[ ! -x "$UTMCTL" ]]; then
  printf 'utmctl not found at %s (set UTMCTL=<path> to override)\n' "$UTMCTL" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  printf 'python3 is required for JSON parsing\n' >&2
  exit 2
fi
if ! command -v nc >/dev/null 2>&1; then
  printf 'nc (netcat) is required for SSH port probing\n' >&2
  exit 2
fi

cd "$REPO_ROOT"

printf '== Discovering UTM VMs (cargo run ops vm-lab-discover-local-utm) ==\n'
discovery_json="$(cargo run --quiet --bin rustynet-cli -- ops vm-lab-discover-local-utm 2>/dev/null)"

# Parse: TSV rows of "name<TAB>platform<TAB>live_ip<TAB>ssh_status".
# We substitute "_" for empty fields because macOS bash 3.2's `read` with a
# custom IFS collapses adjacent separators (POSIX-style for default IFS but
# bash 3.2 applies it to custom IFS too), so two consecutive tabs would
# silently merge and shift the SSH-status into the IP variable.
parsed_tsv="$(printf '%s' "$discovery_json" | python3 -c '
import json, sys
d = json.load(sys.stdin)
for e in d.get("entries", []):
    name = e.get("utm_name") or "_"
    platform = e.get("platform") or "unknown"
    ip = e.get("live_ip") or "_"
    ssh_status = e.get("ssh_port_status") or "_"
    print(f"{name}\t{platform}\t{ip}\t{ssh_status}")
')"

# Parallel arrays keyed by index. bash 3.2 does not support associative
# arrays; helper lookups walk the parallel slices.
ALL_NAMES=()
ALL_IPS=()
ALL_PLATFORMS=()
STUCK_LINUX=()
STUCK_OTHER=()
NO_IP=()

printf '\n%-25s  %-10s  %-18s  %-12s\n' 'NAME' 'PLATFORM' 'LIVE IP' 'SSH:22'
printf -- '-%.0s' {1..72}; printf '\n'
while IFS=$'\t' read -r name platform ip ssh_status; do
  [[ -z "$name" || "$name" == "_" ]] && continue
  # Sentinel "_" means missing — re-substitute empty for downstream logic.
  [[ "$ip" == "_" ]] && ip=""
  [[ "$ssh_status" == "_" ]] && ssh_status=""
  ALL_NAMES+=("$name")
  ALL_IPS+=("$ip")
  ALL_PLATFORMS+=("$platform")
  printf '%-25s  %-10s  %-18s  %-12s\n' "$name" "$platform" "${ip:-—}" "${ssh_status:-—}"
  if [[ -z "$ip" ]]; then
    NO_IP+=("$name")
  elif [[ "$ssh_status" == "open" ]]; then
    :
  elif [[ "$platform" == "linux" ]]; then
    STUCK_LINUX+=("$name|$ip")
  else
    STUCK_OTHER+=("$name|$ip|$platform")
  fi
done <<< "$parsed_tsv"

if (( ${#NO_IP[@]} > 0 )); then
  printf '\nNo live IP discovered for: %s\n' "${NO_IP[*]}"
  printf '  Linux/Windows VMs: most likely powered off or still booting; start/wait then re-run.\n'
  printf '  macOS VMs: UTM Apple Virtualization backend does not expose `utmctl ip-address`.\n'
  printf '             Look up the IP from the host ARP table by the VM MAC (visible in UTM\n'
  printf '             VM settings → Network), then probe TCP/22 manually. Example:\n'
  printf '               arp -a | grep -i <vm-mac>\n'
fi

if (( ${#STUCK_LINUX[@]} == 0 && ${#STUCK_OTHER[@]} == 0 )); then
  printf '\nAll discovered VMs with a live IP are SSH-reachable. Nothing to recover.\n'
  exit 0
fi

if (( ${#STUCK_LINUX[@]} > 0 )); then
  printf '\n== Linux VMs needing utmctl exec recovery ==\n'
  for entry in "${STUCK_LINUX[@]}"; do
    IFS='|' read -r name ip <<< "$entry"
    printf '  %s @ %s\n' "$name" "$ip"
  done

  printf '\n== Running flush + stop on each ==\n'
  for entry in "${STUCK_LINUX[@]}"; do
    IFS='|' read -r name ip <<< "$entry"
    printf '\n--- %s ---\n' "$name"
    # The killswitch's `policy drop` on OUTPUT is what blocks the SYN-ACK
    # from leaving the guest, so flushing the whole ruleset is what makes
    # SSH reachable. Stopping the daemons prevents an immediate re-apply.
    if ! "$UTMCTL" exec "$name" --cmd /usr/bin/sudo nft flush ruleset; then
      printf '  WARN: nft flush returned non-zero (continuing)\n' >&2
    fi
    "$UTMCTL" exec "$name" --cmd /usr/bin/sudo systemctl stop rustynetd 2>/dev/null || true
    "$UTMCTL" exec "$name" --cmd /usr/bin/sudo systemctl stop rustynetd-privileged-helper 2>/dev/null || true
    printf '  ok\n'
  done
fi

if (( ${#STUCK_OTHER[@]} > 0 )); then
  printf '\n== Non-Linux VMs stuck ==\n'
  for entry in "${STUCK_OTHER[@]}"; do
    IFS='|' read -r name ip platform <<< "$entry"
    case "$platform" in
      windows)
        # windows-utm-1 is a QEMU/VirtIO guest with a working guest agent, so
        # `utmctl exec` drives recovery from the host without SSH (verified
        # 2026-05-31; the "Apple-Virt / no utmctl exec" assumption was wrong for
        # this VM). The usual lockout is the RustyNet killswitch leaving the
        # Windows Firewall at AllowInbound,BlockOutbound — inbound SSH is
        # accepted but the guest's outbound SYN-ACK/ICMP replies are dropped, so
        # the host sees TCP/22 + ping timeouts. Recovery: stop the daemon, set it
        # to demand-start (no auto-relock on reboot), let it settle, then restore
        # the outbound firewall policy. Idempotent: re-running on an already-
        # recovered guest is a no-op (sc stop on a stopped service is harmless;
        # the firewall flip is the same value).
        printf '\n--- %s [windows] @ %s — utmctl exec recovery ---\n' "$name" "$ip"
        if "$UTMCTL" exec "$name" --cmd cmd.exe /c "sc stop RustyNet & sc stop RustyNetPrivilegedHelper & sc config RustyNet start= demand & ping -n 5 127.0.0.1 >nul & netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound"; then
          printf '  ok (daemon stopped + demand-start, outbound firewall restored)\n'
        else
          # `utmctl exec` returns the guest command's exit code. The chain ends
          # with `netsh ... set` so a non-zero result means the firewall flip
          # itself failed (no elevated guest agent) — fall back to manual.
          printf '  WARN: utmctl exec recovery failed (no guest agent / not elevated on this VM)\n' >&2
          printf '    Recover via UTM serial console / RDP:\n'
          printf '      sc.exe stop RustyNet\n'
          printf '      netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound\n'
        fi
        ;;
      macos)
        # macOS guests run under UTM's Apple Virtualization backend, which does
        # NOT expose `utmctl exec` — recovery stays manual via the console.
        printf '\n--- %s [macos] @ %s — manual recovery (no utmctl exec) ---\n' "$name" "$ip"
        printf '    via UTM serial console / VNC:\n'
        printf '      sudo launchctl bootout system/com.rustynet.daemon 2>/dev/null || true\n'
        printf '      sudo launchctl bootout system/com.rustynet.privileged-helper 2>/dev/null || true\n'
        printf '      sudo pfctl -F all -d 2>/dev/null || true\n'
        ;;
      *)
        printf '\n--- %s [%s] @ %s — manual recovery required ---\n' "$name" "$platform" "$ip"
        ;;
    esac
  done
fi

printf '\n== Re-probing TCP/22 on every VM with a live IP ==\n'
printf '%-25s  %-18s  %s\n' 'NAME' 'IP' 'TCP/22'
printf -- '-%.0s' {1..58}; printf '\n'
all_ok=1
count=${#ALL_NAMES[@]}
i=0
while (( i < count )); do
  name="${ALL_NAMES[$i]}"
  ip="${ALL_IPS[$i]}"
  i=$((i + 1))
  [[ -z "$ip" ]] && continue
  if nc -zv -G 1 -w 1 "$ip" 22 >/dev/null 2>&1; then
    printf '%-25s  %-18s  OPEN\n' "$name" "$ip"
  else
    printf '%-25s  %-18s  closed/timeout\n' "$name" "$ip"
    all_ok=0
  fi
done

if (( all_ok == 1 )); then
  printf '\nAll VMs reachable. Lab ready for orchestrator retry.\n'
  exit 0
fi
printf '\nSome VMs are still unreachable. See manual recovery notes above.\n' >&2
exit 1
