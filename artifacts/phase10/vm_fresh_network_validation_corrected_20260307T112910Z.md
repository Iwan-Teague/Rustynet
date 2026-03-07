# VM Fresh Install + Network Validation (Corrected)

Generated: 2026-03-07T11:30:00Z
Commit under test: `f85da6e` (`main`)

## Scope
- Full clean reinstall/rebootstrap on reachable Linux VM matrix:
  - Debian `192.168.18.49` (admin/exit)
  - Debian `192.168.18.50` (client)
  - Fedora `192.168.18.51` (client)
  - Mint `192.168.18.53` (client)
- Previous baseline installer run evidence:
  - `/tmp/run_four_node_new_envs.sh` completed with all four nodes active and signed assignment distribution complete.
- Note: Ubuntu `192.168.18.46` remained unreachable in this pass.

## Fresh Install Outcome
- Old Rustynet runtime state was removed and reinstalled from latest local `main` source archive.
- `rustynetd`, `rustynetd-privileged-helper`, trust/assignment refresh timers active on all four reachable VMs.
- Signed membership and assignment artifacts redistributed and enforced.

## Runtime Status (Post-Restore)
- `exit-49`: `node_role=admin`, `state=ExitActive`, `serving_exit_node=true`, `encrypted_key_store=true`.
- `client-50`: `node_role=client`, `state=ExitActive`, `exit_node=exit-49`, `encrypted_key_store=true`.
- `client-51`: `node_role=client`, `state=ExitActive`, `exit_node=exit-49`, `encrypted_key_store=true`.
- `client-53`: `node_role=client`, `state=ExitActive`, `exit_node=exit-49`, `encrypted_key_store=true`.

## Tunnel Routing Evidence
`ip -4 route get 1.1.1.1` on each client:
- Debian client: `dev rustynet0 table 51820 src 100.68.175.216`
- Fedora client: `dev rustynet0 table 51820 src 100.82.160.108`
- Mint client: `dev rustynet0 table 51820 src 100.76.206.118`

## Exit NAT/Forwarding Evidence
On Debian exit (`192.168.18.49`):
- nftables tables include:
  - `table inet rustynet_g6`
  - `table ip rustynet_nat_g6`
- Ruleset includes:
  - `iifname "rustynet0" oifname "enp0s9" accept`
  - `oifname "enp0s9" masquerade`

## Role-Switch Validation
### Mint (`client-53`) controlled switch
- `client -> admin -> client` completed successfully using systemd install path.
- Final state restored: `node_role=client`, `exit_node=exit-49`, `state=ExitActive`.

### Fedora (`client-51`) blind-exit behavior and restore
- Switched to `blind_exit` successfully (`node_role=blind_exit`, `exit_node=none`, `serving_exit_node=true`).
- Daemon restart timing can briefly make `/run/rustynet/rustynetd.sock` unavailable during immediate post-switch probes; resolved after service settle.
- Restored to `client` successfully; final state `exit_node=exit-49`, `state=ExitActive`.

## Security-Relevant Observations
- Encrypted key custody remained enabled and key file mode remained restrictive (`600 rustynetd rustynetd`) on all reachable VMs.
- No unsigned control-plane mutation path was required for provisioning/recovery in this run.
- Client role mutation denial confirmed on all clients:
  - `rustynet route advertise 10.250.0.0/16` returns `error: command denied: current node role does not permit this operation` with exit code `1`.
- Blind-exit least-knowledge command restrictions confirmed on Fedora:
  - `rustynet exit-node select exit-49` denied with exit code `1`.
  - `rustynet lan-access on` denied with exit code `1`.

## Result
- Reachable VM matrix pass: **PASS**
- Blocking issue remaining for full matrix: **Ubuntu node unreachable** (not validated in this run).

## Related Evidence
- Initial detailed run log (contains noisy route-check command typo and non-blocking assertion mismatch):
  - `artifacts/phase10/vm_fresh_network_validation_20260307T112553Z.md`
