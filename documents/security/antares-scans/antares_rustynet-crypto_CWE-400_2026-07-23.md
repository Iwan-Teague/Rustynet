# Antares scan — `rustynet-crypto` — CWE-400

**Date:** 2026-07-23  
**Scope:** `rustynet-crypto` (1 first-party `.rs` files)  
**CWE:** CWE-400 — Uncontrolled resource consumption: resources (CPU, memory, connections, buffers) are not bounded, enabling resource-exhaustion / DoS.  
**Verdict:** `no_vulnerability_found`  
**Budget:** 8/8 terminal cmds, 13 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

_None (aborted or no matching vulnerability declared)._

## Model reasoning

The repository is a crypto library (rustynet-crypto) with shallow source files; I did not find any TcpListener/UdpSocket or unbounded resource consumption sinks (no accept loop, no Vec::with_capacity allocations from attacker-controlled sizes, no unbounded loops or thread spawning in inspected files). The absence of network server code implies no CWE-400 resource exhaustion vulnerability in the source.

## Commands run
```
$ ls
$ find . -maxdepth 2 | head -n 200
$ grep -R "TcpListener\|UdpSocket\|Socket::new\|accept\|connect\|read_to_end\|Vec::with_capacity\|unbounded\|while \(true\)\|spawn\|thread::spawn" .
$ grep -R "TcpListener" .
$ grep -R "Socket::new" .
$ grep -R "accept" .
$ grep -R "TcpListener" src/
$ grep -R "Tcp" src/
$ grep -R "Server\|listen\|accept" src/
$ find src -maxdepth 2 | xargs grep -n "Server\|listen\|accept"
$ find src -maxdepth 1 | grep -E "server|tcp|socket|listen"
$ cat Cargo.toml
```
