# Antares scan — `rustynet-backend-api` — CWE-20

**Date:** 2026-07-23  
**Scope:** `rustynet-backend-api` (3 first-party `.rs` files)  
**CWE:** CWE-20 — Improper input validation: input is not validated (or is validated incorrectly) before use, allowing malformed or malicious data to alter control/data flow.  
**Verdict:** `vulnerable_files`  
**Budget:** 13/15 terminal cmds, 17 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/lib.rs` | inspected |

## Model reasoning

The vulnerability is in src/lib.rs in the NodeId::new implementation. It trims whitespace but does not validate that the trimmed value is non-empty after trimming, allowing a whitespace-only node id to pass validation and be used as a NodeId. This is an improper input validation issue (CWE-20) where malformed/malicious input (whitespace-only node id) can alter control flow and be accepted as valid.

## Commands run
```
$ ls -la /workspace/repo/
$ find . -maxdepth 2 | head -n 80
$ cat Cargo.toml
$ cat src/lib.rs
$ wc -l src/lib.rs
$ grep -RIn "NodeId\." src/
$ grep -RIn "SocketAddr\|IpAddr\|Duration\|Vec\<u8\>" src/
$ grep -RIn "SocketAddr\|IpAddr\|Duration\|Vec<u8>" src/
$ grep -RIn "SocketAddr" src/
$ grep -RIn "new_from_str\|new_from_owned\|trim\(|is_empty()" src/
$ grep -RIn "new_from_str" src/
$ grep -RIn "NodeId::new" src/
$ sed -n '320,350p' src/lib.rs
$ grep -RIn "new_from_str" src/
$ grep -RIn "impl.*new_from_str" src/
$ grep -RIn "new_from_str" src/lib.rs
```
