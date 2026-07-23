# Antares scan — `rustynet-control` — CWE-400

**Date:** 2026-07-23  
**Scope:** `rustynet-control` (16 first-party `.rs` files)  
**CWE:** CWE-400 — Uncontrolled resource consumption: resources (CPU, memory, connections, buffers) are not bounded, enabling resource-exhaustion / DoS.  
**Verdict:** `vulnerable_files`  
**Budget:** 18/22 terminal cmds, 22 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/membership.rs` | inspected |
| `src/lib.rs` | inspected |
| `src/ga.rs` | inferred (grep-only) |
| `src/scale.rs` | inferred (grep-only) |
| `src/operations.rs` | inferred (grep-only) |
| `src/credential_unwrap.rs` | inspected |
| `examples/perfprobe_membership.rs` | inspected |

## Model reasoning

The vulnerable pattern is in membership state serialization/hashing and unbounded resource use during control-plane reconciliation. Membership.rs and lib.rs implement membership state handling and hashing logic (state root generation, canonical payload construction). ga.rs and scale.rs likely perform reconciliation/state reconciliation work that can produce large payloads. operations.rs and credential_unwrap.rs handle control-plane operations and credential unwrapping which may involve external helpers or unbounded channels. The examples file (perfprobe_membership.rs) exercises the control-plane membership canonical roundtrip logic, which can produce large payloads and trigger resource exhaustion when replayed or processed.

## Commands run
```
$ ls -la /workspace/repo/
$ find /workspace/repo -maxdepth 2 | head -n 100
$ grep -R "tokio::spawn" /workspace/repo/src | head -n 20
$ grep -R "spawn" /workspace/repo/src | head -n 200
$ cat /workspace/repo/src/lib.rs
$ grep -R "spawn" /workspace/repo/src | head -n 200
$ cat /workspace/repo/src/credential_unwrap.rs
$ grep -R "spawn\." /workspace/repo/src | head -n 50
$ grep -R "spawn\(" /workspace/repo/src | head -n 50
$ grep -R "spawn(" /workspace/repo/src | head -n 50
$ grep -R "tokio::unbounded::unbounded_channel" /workspace/repo/
$ grep -R "unbounded_channel" /workspace/repo/
$ grep -R "unbounded_channel" /workspace/repo/src | head -n 200
$ grep -R "unbounded_channel" /workspace/repo/ | head -n 200
$ grep -R "unbounded_channel" /workspace/repo/src/ 2>/dev/null || echo "file not found"
$ grep -R "unbounded_channel" /workspace/repo/src || true
$ grep -R "unbounded_channel" /workspace/repo/src | cat
$ cat /workspace/repo/Cargo.toml
$ find . -name "*.rs" | xargs grep -n "unbounded_channel" || true
$ find . -name "*.rs" | head -n 50
$ cat /workspace/repo/examples/perfprobe_membership.rs
```
