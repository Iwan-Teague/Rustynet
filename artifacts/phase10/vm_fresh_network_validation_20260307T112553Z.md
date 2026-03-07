# VM Fresh Network Validation

Generated: 2026-03-07T11:25:53Z

## Baseline Service + Tunnel Checks

### exit-49 (debian@192.168.18.49)
- status: `node_id=exit-49 node_role=admin state=ExitActive generation=4 exit_node=none serving_exit_node=true lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=350 reconcile_failures=0 last_reconcile_unix=1772882753 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true auto_port_forward_exit=false port_forward_external_port=none port_forward_error=none last_assignment=1772882661:1772882661212033802 membership_epoch=4 membership_active_nodes=4`
- expected_role: `admin`, observed_role: `admin`
- state: `ExitActive`, encrypted_key_store: `true`
- exit_node: `none`, serving_exit_node: `true`
- service states:
```text
[sudo] password for debian: tempo
active
active
active
active
```
- rustynet0 interface: `rustynet0`
- encrypted key custody file mode: `[sudo] password for debian: tempo
600 rustynetd rustynetd`

### client-50 (debian@192.168.18.50)
- status: `node_id=client-50 node_role=client state=ExitActive generation=3 exit_node=exit-49 serving_exit_node=false lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=333 reconcile_failures=0 last_reconcile_unix=1772882754 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true auto_port_forward_exit=false port_forward_external_port=none port_forward_error=none last_assignment=1772882667:1772882667376207163 membership_epoch=4 membership_active_nodes=4`
- expected_role: `client`, observed_role: `client`
- state: `ExitActive`, encrypted_key_store: `true`
- exit_node: `exit-49`, serving_exit_node: `false`
- service states:
```text
[sudo] password for debian: tempo
active
active
active
active
```
- rustynet0 interface: `rustynet0`
- encrypted key custody file mode: `[sudo] password for debian: tempo
600 rustynetd rustynetd`

### client-51 (fedora@192.168.18.51)
- status: `node_id=client-51 node_role=client state=ExitActive generation=3 exit_node=exit-49 serving_exit_node=false lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=356 reconcile_failures=0 last_reconcile_unix=1772882755 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true auto_port_forward_exit=false port_forward_external_port=none port_forward_error=none last_assignment=1772882672:1772882672475229010 membership_epoch=4 membership_active_nodes=4`
- expected_role: `client`, observed_role: `client`
- state: `ExitActive`, encrypted_key_store: `true`
- exit_node: `exit-49`, serving_exit_node: `false`
- service states:
```text
[sudo] password for fedora: tempo
active
active
active
active
```
- rustynet0 interface: `rustynet0`
- encrypted key custody file mode: `[sudo] password for fedora: tempo
600 rustynetd rustynetd`

### client-53 (mint@192.168.18.53)
- status: `node_id=client-53 node_role=client state=ExitActive generation=3 exit_node=exit-49 serving_exit_node=false lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=357 reconcile_failures=0 last_reconcile_unix=1772882757 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true auto_port_forward_exit=false port_forward_external_port=none port_forward_error=none last_assignment=1772882684:1772882684659364840 membership_epoch=4 membership_active_nodes=4`
- expected_role: `client`, observed_role: `client`
- state: `ExitActive`, encrypted_key_store: `true`
- exit_node: `exit-49`, serving_exit_node: `false`
- service states:
```text
[sudo] password for mint: tempo
active
active
active
active
```
- rustynet0 interface: `rustynet0`
- encrypted key custody file mode: `[sudo] password for mint: tempo
600 rustynetd rustynetd`

## Route and Restriction Checks

### client restriction: debian@192.168.18.50
- route probe (table 51820):
```text
Error: inet prefix is expected rather than "table".
```
- latest handshakes:
```text
[sudo] password for debian: tempo
mqhdvE3Ef1qXG22/dkBoEMOc6g6vA1GqoPa/YFusU0s=	1772882395
```
- unauthorized route advertise exit code: `0` (expected non-zero)

### client restriction: fedora@192.168.18.51
- route probe (table 51820):
```text
Error: inet prefix is expected rather than "table".
```
- latest handshakes:
```text
[sudo] password for fedora: tempo
mqhdvE3Ef1qXG22/dkBoEMOc6g6vA1GqoPa/YFusU0s=	0
```
- unauthorized route advertise exit code: `0` (expected non-zero)

### client restriction: mint@192.168.18.53
- route probe (table 51820):
```text
Error: inet prefix is expected rather than "table".
```
- latest handshakes:
```text
[sudo] password for mint: tempo
mqhdvE3Ef1qXG22/dkBoEMOc6g6vA1GqoPa/YFusU0s=	0
```
- unauthorized route advertise exit code: `0` (expected non-zero)

### admin route/NAT: debian@192.168.18.49
- advertise 0.0.0.0/0 output: `[sudo] password for debian: tempo
route advertised: 0.0.0.0/0`
- rustynet_nat table:
```text
[sudo] password for debian: tempo
Error: No such file or directory
list table ip rustynet_nat
              ^^^^^^^^^^^^
```

## Controlled Role Switch Check (Mint)
- before: `node_id=client-53 node_role=client state=ExitActive generation=3 exit_node=exit-49 serving_exit_node=false lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=363 reconcile_failures=0 last_reconcile_unix=1772882763 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true auto_port_forward_exit=false port_forward_external_port=none port_forward_error=none last_assignment=1772882684:1772882684659364840 membership_epoch=4 membership_active_nodes=4`
- after switch to admin: `node_id=client-53 node_role=admin state=ExitActive generation=1 exit_node=exit-49 serving_exit_node=false lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=2 reconcile_failures=0 last_reconcile_unix=1772882768 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true auto_port_forward_exit=false port_forward_external_port=none port_forward_error=none last_assignment=1772882684:1772882684659364840 membership_epoch=4 membership_active_nodes=4`
- after switch back to client: `node_id=client-53 node_role=client state=ExitActive generation=1 exit_node=exit-49 serving_exit_node=false lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=2 reconcile_failures=0 last_reconcile_unix=1772882773 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true auto_port_forward_exit=false port_forward_external_port=none port_forward_error=none last_assignment=1772882684:1772882684659364840 membership_epoch=4 membership_active_nodes=4`

## Blind Exit Role Check (Fedora)
- before: `node_id=client-51 node_role=client state=ExitActive generation=3 exit_node=exit-49 serving_exit_node=false lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=374 reconcile_failures=0 last_reconcile_unix=1772882773 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true auto_port_forward_exit=false port_forward_external_port=none port_forward_error=none last_assignment=1772882672:1772882672475229010 membership_epoch=4 membership_active_nodes=4`
- as blind_exit: `node_id=client-51 node_role=blind_exit state=ExitActive generation=2 exit_node=none serving_exit_node=true lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=2 reconcile_failures=0 last_reconcile_unix=1772882782 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true auto_port_forward_exit=false port_forward_external_port=none port_forward_error=none last_assignment=1772882672:1772882672475229010 membership_epoch=4 membership_active_nodes=4`
- blind_exit route advertise exit code: `0` (expected non-zero)
- restored client: `node_id=client-51 node_role=client state=ExitActive generation=1 exit_node=exit-49 serving_exit_node=false lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=3 reconcile_failures=0 last_reconcile_unix=1772882790 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true auto_port_forward_exit=false port_forward_external_port=none port_forward_error=none last_assignment=1772882672:1772882672475229010 membership_epoch=4 membership_active_nodes=4`

## Final Restore Check
- all clients restored to `exit-49` with `state=ExitActive`: PASS

## Overall
PASS
