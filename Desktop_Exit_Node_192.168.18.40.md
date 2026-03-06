# Exit Node Commands (192.168.18.40)

Role verified on 2026-03-05:
- host: `192.168.18.40`
- expected node id: `exit-node`
- expected behavior: serves exit traffic and applies NAT

## 1) SSH In

```bash
ssh debian@192.168.18.40
```

## 2) Validate Exit Node State

```bash
set -euo pipefail
sudo -v
export RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock
sudo RUSTYNET_DAEMON_SOCKET="$RUSTYNET_DAEMON_SOCKET" rustynet status
```

Expected fields in output:
- `node_id=exit-node`
- `serving_exit_node=true`
- `state=ExitActive`

## 3) Ensure Exit Route Is Advertised

```bash
export RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock
sudo RUSTYNET_DAEMON_SOCKET="$RUSTYNET_DAEMON_SOCKET" rustynet route advertise 0.0.0.0/0
sudo RUSTYNET_DAEMON_SOCKET="$RUSTYNET_DAEMON_SOCKET" rustynet status
```

## 4) Confirm NAT + Forward Rules Exist

```bash
sudo sh -c 'nft list ruleset | grep -E "masquerade|iifname \"rustynet0\""' 
```

Expected matches include:
- `masquerade`
- `iifname "rustynet0"`

## 5) Observe NAT on Wire (Terminal A on Exit Node)

```bash
WAN_IF=$(ip -4 route show default | awk '/default/ {print $5; exit}')
sudo tcpdump -ni rustynet0 -c 8 'icmp and host 1.1.1.1'
```

## 6) Observe NAT on Wire (Terminal B on Exit Node)

```bash
WAN_IF=$(ip -4 route show default | awk '/default/ {print $5; exit}')
sudo tcpdump -ni "$WAN_IF" -c 8 'icmp and host 1.1.1.1'
```

Interpretation:
- `rustynet0` capture should show source as client tunnel IP (`100.x.x.x`).
- WAN capture should show source rewritten to exit node WAN IP (`192.168.18.40` or upstream NAT IP).

## 7) Optional WireGuard Health

```bash
sudo wg show rustynet0 latest-handshakes
sudo wg show rustynet0
```
