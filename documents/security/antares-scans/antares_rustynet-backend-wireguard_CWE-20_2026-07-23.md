# Antares scan — `rustynet-backend-wireguard` — CWE-20

**Date:** 2026-07-23  
**Scope:** `rustynet-backend-wireguard` (21 first-party `.rs` files)  
**CWE:** CWE-20 — Improper input validation: input is not validated (or is validated incorrectly) before use, allowing malformed or malicious data to alter control/data flow.  
**Verdict:** `vulnerable_files`  
**Budget:** 18/22 terminal cmds, 19 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/linux_command.rs` | inspected |
| `src/macos_command.rs` | inspected |

## Model reasoning

The vulnerable code in LinuxWireguardBackend::ensure_wireguard_go_on_path and MacosWireguardBackend::ensure_wireguard_go_on_path uses the `which` command to locate the wireguard-go binary and then attempts to run it. The logic incorrectly assumes the binary will be found at a predictable path under `/usr/local/bin/` based on the `which` command's output. If the binary is installed elsewhere (e.g., `/usr/local/bin/wireguard-go`), the code fails to find it because it relies on the `which` output (which would point to the actual location), demonstrating incorrect validation of the binary location. This can lead to the command failing silently or incorrectly determining whether the prerequisite binary is available.

## Commands run
```
$ find . -maxdepth 2 | head -n 100
$ cat ./Cargo.toml
$ grep -R "unwrap()" ./src | head -n 200
$ grep -R "from_str\[" -n . | head -n 200
$ grep -R "SocketAddr" -n . | head -n 200
$ grep -R "parse\(" -n . | head -n 200
$ grep -R "parse_addr" -n . | head -n 200
$ grep -R "from_net_varuint" -n . | head -n 200
$ grep -R "TcpListener" -n . | head -n 200
$ grep -R "TcpStream" -n . | head -n 200
$ grep -R "Socket" -n . | head -n 200
$ cat ./src/udp_offload_probe.rs
$ grep -n "probe_udp_offload_capabilities" ./src/udp_offload_probe.rs
$ cat ./src/userspace_shared_macos/mod.rs
$ grep -R "validate_interface_name" -n . | head -n 200
$ cat ./src/macos_command.rs | head -n 200
$ grep -R "ensure_wireguard_go_on_path" -n .
$ cat ./src/linux_command.rs
```
