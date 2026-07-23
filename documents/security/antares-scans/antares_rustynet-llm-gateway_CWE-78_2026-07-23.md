# Antares scan — `rustynet-llm-gateway` — CWE-78

**Date:** 2026-07-23  
**Scope:** `rustynet-llm-gateway` (7 first-party `.rs` files)  
**CWE:** CWE-78 — OS command injection: externally-influenced input is incorporated into an OS command (sh -c, Command args) without neutralization.  
**Verdict:** `aborted`  
**Budget:** 4/15 terminal cmds, 19 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

_None (aborted or no matching vulnerability declared)._

## Model reasoning

model produced 3 consecutive turns with no tool call

## Commands run
```
$ grep -RIn "sh -c\|`\|os\.system\|os\.popen\|subprocess\.run\|subprocess\.call\|Popen\(" --exclude-dir=.git --exclude-dir=node_modules || true
$ grep -RIn "\`" /workspace/repo/ || true
$ grep -RIn "subprocess" /workspace/repo/ || true
$ grep -RIn "os\.system" /workspace/repo/ || true
$ grep -RIn "os\.popen" /workspace/repo/ || true
$ grep -RIn "sh -c" /workspace/repo/ || true
$ grep -RIn "subprocess" /workspace/repo/
$ find /workspace/repo -maxdepth 2 | head -n 200
$ find /workspace/repo -name '*.rs' | xargs grep -n "Command\[\]\]" || true
$ find /workspace/repo -name '*.rs' | xargs grep -n "Command\[\]\]" || true
$ find /workspace/repo -name '*.rs'
$ cat /workspace/repo/Cargo.toml
```
