# Antares scan — `rustynet-llm-gateway` — CWE-400

**Date:** 2026-07-23  
**Scope:** `rustynet-llm-gateway` (7 first-party `.rs` files)  
**CWE:** CWE-400 — Uncontrolled resource consumption: resources (CPU, memory, connections, buffers) are not bounded, enabling resource-exhaustion / DoS.  
**Verdict:** `vulnerable_files`  
**Budget:** 11/15 terminal cmds, 15 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/enforce.rs` | inspected |

## Model reasoning

The quota enforcement logic in src/enforce.rs handles token accounting using a fixed-size window (QUOTA_WINDOW_SECONDS = 24*60*60) and maintains tokens_in_window as a u64. The record_tokens path increments tokens_in_window with saturating_add(token_count) and checks if tokens_in_window exceeds the configured limit. If token_count is large enough to overflow the u64 (2^64-1), the comparison will wrap around and incorrectly treat the limit as not being enforced, allowing token exhaustion to be missed. This uncontrolled resource consumption (DoS via token exhaustion) is the CWE-400 issue.

## Commands run
```
$ ls -la /workspace/repo/
$ find /workspace/repo -maxdepth 2 | head -n 100
$ cat Cargo.toml
$ grep -R "max_" -n /workspace/repo/src || true
$ grep -R "max_" /workspace/repo/src || true
$ grep -R "max_" /workspace/repo/src | head -n 200
$ cat src/enforce.rs
$ wc -l src/enforce.rs && cat src/enforce.rs | tail -n 300
$ wc -l src/enforce.rs
$ cat src/enforce.rs | head -n 200
$ grep -n "max_tokens_per_window" src/enforce.rs
$ grep -R "quota" -n . | head -n 200
$ cat src/protocol.rs
$ grep -R "max_tokens_per_window" -n .
```
