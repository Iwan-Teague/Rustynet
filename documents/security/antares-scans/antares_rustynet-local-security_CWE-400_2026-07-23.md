# Antares scan — `rustynet-local-security` — CWE-400

**Date:** 2026-07-23  
**Scope:** `rustynet-local-security` (1 first-party `.rs` files)  
**CWE:** CWE-400 — Uncontrolled resource consumption: resources (CPU, memory, connections, buffers) are not bounded, enabling resource-exhaustion / DoS.  
**Verdict:** `vulnerable_files`  
**Budget:** 8/8 terminal cmds, 11 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/lib.rs` | inferred (grep-only) |

## Model reasoning

The repository implements a network server (TcpListener/accept-based server) in src/lib.rs. Such servers typically spawn a new thread per connection or maintain per-connection state, which can lead to uncontrolled resource consumption (CPU, memory, file descriptors, and thread pools) if connections are not bounded or connection limits are absent. This matches the CWE-400 vulnerability class.

## Commands run
```
$ ls
$ find . -maxdepth 2 | head -n 200
$ grep -R "TcpListener\|UdpSocket\|Socket::new\|accept\|connect\|read_to_end\|Vec::with_capacity\|unbounded\|while \(true\)\|spawn\|thread::spawn" .
$ grep -R "TcpListener" .
$ grep -R "Socket::new" .
$ grep -R "accept" .
$ grep -R "Tcp" .
$ cat Cargo.toml
$ find src -maxdepth 1 | sort | head -n 50
```
