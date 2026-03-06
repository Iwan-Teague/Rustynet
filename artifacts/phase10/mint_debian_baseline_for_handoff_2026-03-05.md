# Debian Two-Node Clean Install + Tunnel Validation

- generated_at_utc: 2026-03-05T21:47:41Z
- commit: 94bba6f
- exit_host: mint@192.168.18.44
- client_host: debian@192.168.18.40
- exit_node_id: exit-node
- client_node_id: client-node
- network_id: local-net
- ssh_allow_cidrs: 192.168.18.2/32

## Checks

| Check | Status | Detail |
|---|---|---|
| exit-status-active | PASS | found 'state=ExitActive' |
| exit-serving-enabled | PASS | found 'serving_exit_node=true' |
| exit-not-restricted | PASS | found 'restricted_safe_mode=false' |
| client-status-active | PASS | found 'state=ExitActive' |
| client-exit-selected | PASS | found 'exit_node=exit-node' |
| client-not-restricted | PASS | found 'restricted_safe_mode=false' |
| client-route-via-tunnel | PASS | found 'dev rustynet0' |
| exit-nat-masquerade | PASS | found 'masquerade' |
| exit-forward-from-tunnel | PASS | found 'iifname "rustynet0"' |
| exit-assignment-refresh-timer | PASS | rustynetd-assignment-refresh.timer is active |
| client-assignment-refresh-timer | PASS | rustynetd-assignment-refresh.timer is active |
| exit-tunnel-ip | PASS | 100.117.119.84 |
| wg-latest-handshake | PASS | latest-handshakes includes non-zero timestamp |
| no-plaintext-passphrase-files | PASS | legacy plaintext passphrase files absent |
| credential-blob-permissions | PASS | wg credential blob mode is 0600 root:root on both hosts |
| encrypted-key-permissions | PASS | encrypted key mode is 0600 rustynetd:rustynetd on both hosts |
| exit-assignment-refresh-rotation | PASS | generated_at advanced from 1772747015 to 1772747157 |
| client-assignment-refresh-rotation | PASS | generated_at advanced from 1772747015 to 1772747150 |

## Exit Status

```text
node_id=exit-node node_role=admin state=ExitActive generation=2 exit_node=none serving_exit_node=true lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=7 reconcile_failures=0 last_reconcile_unix=1772747028 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true last_assignment=1772747015:1772747015126037617 membership_epoch=2 membership_active_nodes=2
```

## Exit Status After Assignment Refresh Window

```text
node_id=exit-node node_role=admin state=ExitActive generation=3 exit_node=none serving_exit_node=true lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=215 reconcile_failures=0 last_reconcile_unix=1772747260 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true last_assignment=1772747157:1772747157983282955 membership_epoch=2 membership_active_nodes=2
```

## Client Status

```text
node_id=client-node node_role=client state=ExitActive generation=1 exit_node=exit-node serving_exit_node=false lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=5 reconcile_failures=0 last_reconcile_unix=1772747028 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true last_assignment=1772747015:1772747015126037617 membership_epoch=2 membership_active_nodes=2
```

## Client Status After Assignment Refresh Window

```text
node_id=client-node node_role=client state=ExitActive generation=2 exit_node=exit-node serving_exit_node=false lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=230 reconcile_failures=0 last_reconcile_unix=1772747261 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true last_assignment=1772747150:1772747150021031193 membership_epoch=2 membership_active_nodes=2
```

## Client Route Check

```text
1.1.1.1 dev rustynet0 table 51820 src 100.72.217.180 uid 0 
    cache 
```

## Exit WireGuard

```text
interface: rustynet0
  public key: G9ElP+1yWjrrHvp297iGwA8JDB8BV9GURt29SOQTfBI=
  private key: (hidden)
  listening port: 51820

peer: vUpDXsNJE+TkxScssNIX+My5Eyz/RudcfnukZj5cjBM=
  endpoint: 192.168.18.40:51820
  allowed ips: 100.72.217.180/32
```
