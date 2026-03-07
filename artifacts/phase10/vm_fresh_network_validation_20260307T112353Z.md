# VM Fresh Network Validation

Generated: 2026-03-07T11:23:53Z

## Baseline Service + Tunnel Checks

### exit-49 (debian@192.168.18.49)
- status: ``
- expected_role: `admin`, observed_role: ``
- state: ``, encrypted_key_store: ``
- exit_node: ``, serving_exit_node: ``
- service states:
```text
ssh: connect to host 192.168.18.49 port 22: Operation not permitted
```
- rustynet0 interface: `ssh: connect to host 192.168.18.49 port 22: Operation not permitted`
- encrypted key custody file mode: `ssh: connect to host 192.168.18.49 port 22: Operation not permitted`

### client-50 (debian@192.168.18.50)
- status: ``
- expected_role: `client`, observed_role: ``
- state: ``, encrypted_key_store: ``
- exit_node: ``, serving_exit_node: ``
- service states:
```text
ssh: connect to host 192.168.18.50 port 22: Operation not permitted
```
- rustynet0 interface: `ssh: connect to host 192.168.18.50 port 22: Operation not permitted`
- encrypted key custody file mode: `ssh: connect to host 192.168.18.50 port 22: Operation not permitted`

### client-51 (fedora@192.168.18.51)
- status: ``
- expected_role: `client`, observed_role: ``
- state: ``, encrypted_key_store: ``
- exit_node: ``, serving_exit_node: ``
- service states:
```text
ssh: connect to host 192.168.18.51 port 22: Operation not permitted
```
- rustynet0 interface: `ssh: connect to host 192.168.18.51 port 22: Operation not permitted`
- encrypted key custody file mode: `ssh: connect to host 192.168.18.51 port 22: Operation not permitted`

### client-53 (mint@192.168.18.53)
- status: ``
- expected_role: `client`, observed_role: ``
- state: ``, encrypted_key_store: ``
- exit_node: ``, serving_exit_node: ``
- service states:
```text
ssh: connect to host 192.168.18.53 port 22: Operation not permitted
```
- rustynet0 interface: `ssh: connect to host 192.168.18.53 port 22: Operation not permitted`
- encrypted key custody file mode: `ssh: connect to host 192.168.18.53 port 22: Operation not permitted`

## Route and Restriction Checks

### client restriction: debian@192.168.18.50
- route probe (table 51820):
```text
ssh: connect to host 192.168.18.50 port 22: Operation not permitted
```
- latest handshakes:
```text
ssh: connect to host 192.168.18.50 port 22: Operation not permitted
```
- unauthorized route advertise exit code: `0` (expected non-zero)

### client restriction: fedora@192.168.18.51
- route probe (table 51820):
```text
ssh: connect to host 192.168.18.51 port 22: Operation not permitted
```
- latest handshakes:
```text
ssh: connect to host 192.168.18.51 port 22: Operation not permitted
```
- unauthorized route advertise exit code: `0` (expected non-zero)

### client restriction: mint@192.168.18.53
- route probe (table 51820):
```text
ssh: connect to host 192.168.18.53 port 22: Operation not permitted
```
- latest handshakes:
```text
ssh: connect to host 192.168.18.53 port 22: Operation not permitted
```
- unauthorized route advertise exit code: `0` (expected non-zero)

### admin route/NAT: debian@192.168.18.49
- advertise 0.0.0.0/0 output: `ssh: connect to host 192.168.18.49 port 22: Operation not permitted`
- rustynet_nat table:
```text
ssh: connect to host 192.168.18.49 port 22: Operation not permitted
```
