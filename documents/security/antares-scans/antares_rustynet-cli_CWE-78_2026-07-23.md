# Antares scan — `rustynet-cli` — CWE-78

**Date:** 2026-07-23  
**Scope:** `rustynet-cli` (273 first-party `.rs` files)  
**CWE:** CWE-78 — OS command injection: externally-influenced input is incorporated into an OS command (sh -c, Command args) without neutralization.  
**Verdict:** `error`  
**Budget:** 9/30 terminal cmds, 12 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

_None (aborted or no matching vulnerability declared)._

## Model reasoning

HTTP 500: {"error":{"code":500,"message":"Failed to parse tool call arguments as JSON: [json.exception.parse_error.101] parse error at line 1, column 1295: syntax error while parsing value - invalid string: missing closing quote; last read: '\"src/vm_lab/mod.'","type":"server_error"}}

## Commands run
```
$ ls -la /workspace/repo/
$ find /workspace/repo -maxdepth 2 | head -n 80
$ grep -RIn "Command::new\(|Command::new \(" /workspace/repo/src | head -n 200
$ grep -RIn "Command::new" /workspace/repo/src
$ grep -RIn "sh -c" /workspace/repo/src
$ grep -RIn "Command::new\(.*\)" /workspace/repo/src | head -n 200
$ grep -RIn "sh -c" src | head -n 200
$ cat src/bin/bootstrap_ci_tools.rs
$ grep -RIn "sh -c" src | head -n 200
$ grep -RIn "Command::new\(" /workspace/repo/src | head -n 200
```
