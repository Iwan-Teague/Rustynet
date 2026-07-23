# Antares scan — `rustynet-advisor` — CWE-400

**Date:** 2026-07-23  
**Scope:** `rustynet-advisor` (2 first-party `.rs` files)  
**CWE:** CWE-400 — Uncontrolled resource consumption: resources (CPU, memory, connections, buffers) are not bounded, enabling resource-exhaustion / DoS.  
**Verdict:** `vulnerable_files`  
**Budget:** 8/8 terminal cmds, 13 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/lib.rs` | inferred (grep-only) |

## Model reasoning

The repository is a small Rust project with only src/lib.rs. The absence of network server code (TcpListener/UdpSocket/accept) suggests the vulnerability resides in the main implementation logic rather than an external network handler. The single source file is therefore the most likely location for uncontrolled resource consumption (e.g., unbounded loops, unbounded buffer growth, or resource allocation without limits).

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
$ grep -R "accept" src
$ grep -R "Tcp" src
```
