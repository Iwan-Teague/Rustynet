# Antares scan — `rustynet-dns-zone` — CWE-400

**Date:** 2026-07-23  
**Scope:** `rustynet-dns-zone` (1 first-party `.rs` files)  
**CWE:** CWE-400 — Uncontrolled resource consumption: resources (CPU, memory, connections, buffers) are not bounded, enabling resource-exhaustion / DoS.  
**Verdict:** `vulnerable_files`  
**Budget:** 8/8 terminal cmds, 10 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/lib.rs` | inferred (grep-only) |

## Model reasoning

src/lib.rs allocates Vecs with capacity based on attacker-controlled counts (record_count and bytes.len()), which can lead to unbounded memory allocation and memory exhaustion (CWE-400).

## Commands run
```
$ ls
$ find . -maxdepth 2 | head -n 200
$ grep -R "TcpListener\|UdpSocket\|Socket::new\|accept\|connect\|read_to_end\|Vec::with_capacity\|unbounded\|while \(true\)\|spawn\|thread::spawn" .
$ grep -R "TcpListener" .
$ grep -R "Socket::new" .
$ grep -R "accept" .
$ grep -R "TcpListener" src/
$ grep -R "read_to_end" src/
$ grep -R "Vec::with_capacity" src/
```
