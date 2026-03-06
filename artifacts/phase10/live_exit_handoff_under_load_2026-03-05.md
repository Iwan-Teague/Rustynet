# Live Exit Handoff Under Load Validation

- generated_at_utc: 2026-03-05T22:51:31Z
- commit: f693334
- exit_a_host: mint@192.168.18.44
- exit_b_host: debian@192.168.18.37
- client_host: debian@192.168.18.40
- switch_iteration: 25
- switch_timestamp_unix: 1772751024
- monitor_log: /Users/iwanteague/Desktop/Rustynet/artifacts/phase10/live_exit_handoff_monitor_2026-03-05.log

## Checks

| Check | Status | Detail |
|---|---|---|
| handoff-reconvergence | PASS | client switched to exit-node-b in 1s |
| no-route-leak-during-handoff | PASS | all monitor samples kept route via rustynet0 |
| no-restricted-safe-mode | PASS | client stayed out of restricted safe mode during monitor window |
| exit-b-handshake | PASS | client has non-zero handshake with endpoint 192.168.18.37 |
| both-exits-nat | PASS | masquerade rule present on both exits |

## Final Client Status

```text
node_id=client-node node_role=client state=ExitActive generation=2 exit_node=exit-node-b serving_exit_node=false lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=103 reconcile_failures=0 last_reconcile_unix=1772751090 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true last_assignment=1772751024:1772751024874413520 membership_epoch=3 membership_active_nodes=3
```

## Final Exit A Status

```text
node_id=exit-node node_role=admin state=ExitActive generation=2 exit_node=none serving_exit_node=true lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=97 reconcile_failures=0 last_reconcile_unix=1772751090 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true last_assignment=1772750973:1772750973374700593 membership_epoch=3 membership_active_nodes=3
```

## Final Exit B Status

```text
node_id=exit-node-b node_role=admin state=ExitActive generation=2 exit_node=none serving_exit_node=true lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=111 reconcile_failures=0 last_reconcile_unix=1772751091 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true last_assignment=1772750973:1772750973379700129 membership_epoch=3 membership_active_nodes=3
```

## Final Client Route

```text
1.1.1.1 dev rustynet0 table 51820 src 100.72.217.180 uid 0 
    cache 
```

## Final Client WireGuard Dump

```text
sDoaQg/wA87HIv7kwMP38sj0EaZpWYQ6E++xGOccolI=	vUpDXsNJE+TkxScssNIX+My5Eyz/RudcfnukZj5cjBM=	51820	off
G9ElP+1yWjrrHvp297iGwA8JDB8BV9GURt29SOQTfBI=	(none)	192.168.18.44:51820	100.117.119.84/32	1772750989	3292	3748	off
lTOSffDs4V6M8LWswYT2zhOsuMdGrBMy375Y46KQ8Bg=	(none)	192.168.18.37:51820	0.0.0.0/0,100.89.224.18/32	1772751026	5852	6276	off
```
