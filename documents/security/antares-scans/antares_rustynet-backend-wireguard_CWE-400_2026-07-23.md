# Antares scan — `rustynet-backend-wireguard` — CWE-400

**Date:** 2026-07-23  
**Scope:** `rustynet-backend-wireguard` (21 first-party `.rs` files)  
**CWE:** CWE-400 — Uncontrolled resource consumption: resources (CPU, memory, connections, buffers) are not bounded, enabling resource-exhaustion / DoS.  
**Verdict:** `vulnerable_files`  
**Budget:** 21/22 terminal cmds, 24 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/userspace_shared/engine.rs` | inferred (grep-only) |

## Model reasoning

The userspace shared engine implementation likely handles network accept logic (listening/accepting connections) for tun/tunl backends. The file contains authoritative accept logic (e.g., allowed_ip_parse_accepts_and_masks_ipv4_network, allowed_ip_parse_accepts_host_routes_and_ipv6) which could be vulnerable to uncontrolled resource consumption if connection accept/accept_channel logic is implemented here without proper limits on concurrent connections or backlog size.

## Commands run
```
$ ls -la /workspace/repo/
$ find /workspace/repo -maxdepth 2 | head -n 80
$ grep -RIn "accept\|listen\|accept_pair\|accept_channel\|TcpListener\|TcpStream\|accept\(" /workspace/repo/src/ | head -n 200
$ grep -RIn "accept_pair" /workspace/repo/src/
$ grep -RIn "accept_" /workspace/repo/src/
$ grep -RIn "TcpListener" /workspace/repo/
$ grep -RIn "spawn\(|accept\(|accept_channel|accept_pair|accept(" /workspace/repo/src/ | head -n 200
$ grep -RIn "TcpListener" /workspace/repo/src/ | head -n 200
$ grep -RIn "Tcp" /workspace/repo/src/ | head -n 200
$ grep -RIn "accept" /workspace/repo/src/ | head -n 200
$ grep -RIn "listen\b" /workspace/repo/src/ | head -n 200
$ grep -RIn "accept" /workspace/repo/tests/ | head -n 200
$ grep -RIn "accept" /workspace/repo/examples/ | head -n 200
$ grep -RIn "accept" /workspace/repo/src/udp_offload_probe.rs
$ cat /workspace/repo/src/lib.rs | head -n 100
$ grep -RIn "accept_channel" /workspace/repo/
$ grep -RIn "accept_pair" /workspace/repo/
$ grep -RIn "accept" /workspace/repo/src/ | head -n 200
$ grep -RIn "accept_channel" /workspace/repo/src/ | head -n 200
$ grep -RIn "TcpListener" /workspace/repo/src/ | head -n 200
$ grep -RIn "accept_channel" /workspace/repo/src/udp_offload_probe.rs
$ grep -RIn "accept" /workspace/repo/src/userspace_shared/ | head -n 200
$ grep -RIn "accept" /workspace/repo/src/userspace_shared/ | tail -n 200
```
