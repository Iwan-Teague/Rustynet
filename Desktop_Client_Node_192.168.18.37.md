# Client Node Commands (192.168.18.37)

Role verified on 2026-03-05:
- host: `192.168.18.37`
- expected node id: `client-node`
- expected behavior: routes internet traffic via exit node `exit-node`

## 1) SSH In

```bash
ssh debian@192.168.18.37
```

## 2) Validate Client State

```bash
set -euo pipefail
sudo -v
export RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock
sudo RUSTYNET_DAEMON_SOCKET="$RUSTYNET_DAEMON_SOCKET" rustynet status
```

Expected fields in output:
- `node_id=client-node`
- `exit_node=exit-node`
- `state=ExitActive`

## 3) Confirm Default Route Uses Tunnel

```bash
ip -4 route get 1.1.1.1
```

Expected output includes:
- `dev rustynet0`

## 4) Generate Test Traffic (For NAT Verification on Exit Node)

```bash
ping -c 8 1.1.1.1
```

Run this while packet capture is active on the exit node.

## 5) Optional External IP Check

```bash
curl -4 --max-time 10 https://ifconfig.me
```

Expected: external IP resolves to the exit path (not a direct client egress identity).

## 6) Optional WireGuard Health

```bash
sudo wg show rustynet0 latest-handshakes
sudo wg show rustynet0
```

## 7) Key-Custody Security Spot Check

```bash
sudo ls -l /etc/rustynet/credentials/wg_key_passphrase.cred /var/lib/rustynet/keys/wireguard.key.enc
if sudo test -e /var/lib/rustynet/keys/wireguard.passphrase || sudo test -e /etc/rustynet/wireguard.passphrase; then
  echo "FAIL: plaintext passphrase file present"
else
  echo "PASS: plaintext passphrase files absent"
fi
```

Expected:
- credential blob: `root:root` `0600`
- encrypted key: `rustynetd:rustynetd` `0600`
- plaintext passphrase files should not exist
