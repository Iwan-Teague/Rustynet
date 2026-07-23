# Antares scan — `rustynet-backend-userspace` — CWE-400

**Date:** 2026-07-23  
**Scope:** `rustynet-backend-userspace` (2 first-party `.rs` files)  
**CWE:** CWE-400 — Uncontrolled resource consumption: resources (CPU, memory, connections, buffers) are not bounded, enabling resource-exhaustion / DoS.  
**Verdict:** `vulnerable_files`  
**Budget:** 8/8 terminal cmds, 14 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/lib.rs` | inferred (grep-only) |

## Model reasoning

The repository contains a backend implementation (src/lib.rs) that likely handles network/userspace communication and may allocate buffers or spawn accept loops for connections. This is the most likely location for CWE-400 uncontrolled resource consumption issues (unbounded buffers, unbounded connections, or unbounded resource allocation).

## Commands run
```
$ ls
$ find . -maxdepth 2 | grep -E "src|Cargo\.toml"
$ find src -maxdepth 2 | grep -E "server|http|request|tcp|udp|listen|accept"
$ find src -maxdepth 1 | grep -E "server|http|request|tcp|udp|listen|accept"
$ find src -maxdepth 1
$ grep -R "Server\.|TcpListener\.|UdpSocket\.|Udp\(" src
$ grep -R "TcpListener" src
$ grep -R "TcpListener" src
$ grep -R "Server" src
$ grep -R "listen" src
$ grep -R "buffer\.|recv\.|send\.|recvmsg\.|recvfrom\.|sendmsg\.|allocate\(" src
$ grep -R "buffer" src
$ grep -R "recv" src
```
