# Antares scan — `rustynet-mcp` — CWE-400

**Date:** 2026-07-23  
**Scope:** `rustynet-mcp` (6 first-party `.rs` files)  
**CWE:** CWE-400 — Uncontrolled resource consumption: resources (CPU, memory, connections, buffers) are not bounded, enabling resource-exhaustion / DoS.  
**Verdict:** `vulnerable_files`  
**Budget:** 7/15 terminal cmds, 9 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/lib.rs` | inspected |

## Model reasoning

The MCP library implements JSON-RPC 2.0 over stdio and performs unbounded resource consumption patterns. src/lib.rs contains the core implementation (repo root resolution via env::var/env::option_env, JSON-RPC request handling, and server initialization). The code opens server endpoints and processes requests sequentially without any per-connection or per-request resource limits (e.g., per-connection buffer sizes, request queueing, or timeout enforcement). This allows an attacker to send many requests to a server and exhaust memory/CPU/connections, leading to resource exhaustion and denial of service. The build script sets RUSTYNET_REPO_BAKED (build provenance), which the library uses to resolve the repository root, but the core library itself lacks resource-bound handling for incoming RPC processing.

## Commands run
```
$ ls -la /workspace/repo/
$ find . -maxdepth 2 | head -n 80
$ cat Cargo.toml
$ cat build.rs
$ find src -maxdepth 2 | head -n 40
$ cat src/lib.rs
$ wc -l src/lib.rs && tail -n 100 src/lib.rs
$ wc -l src/lib.rs
```
