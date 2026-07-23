# Antares scan — `rustynet-mcp` — CWE-78

**Date:** 2026-07-23  
**Scope:** `rustynet-mcp` (6 first-party `.rs` files)  
**CWE:** CWE-78 — OS command injection: externally-influenced input is incorporated into an OS command (sh -c, Command args) without neutralization.  
**Verdict:** `vulnerable_files`  
**Budget:** 8/15 terminal cmds, 24 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/bin/gate_runner.rs` | inspected |

## Model reasoning

The vulnerable code constructs and runs shell commands from externally influenced scope tokens. In src/bin/gate_runner.rs, the unsafe_scope_token branch builds args and calls self.run_command("cargo", &args, 600) for each scope token. The shell invocation is externally influenced (scope tokens), and the code does not neutralize or validate the command arguments, enabling OS command injection (CWE-78). The accompanying tests show the gating behavior and demonstrate the unsafe_scope_token behavior.

## Commands run
```
$ grep -RIn "sh -c\|`\|os\.system\|os\.popen\|subprocess\.run\|subprocess\.call\|Popen\(" --exclude-dir=.git --exclude-dir=node_modules || true
$ grep -RIn "\`" /workspace/repo/ || true
$ grep -RIn "subprocess" /workspace/repo/ || true
$ grep -RIn "os\.system" /workspace/repo/ || true
$ grep -RIn "os\.popen" /workspace/repo/ || true
$ grep -RIn "sh -c" /workspace/repo/ || true
$ grep -RIn "subprocess" /workspace/repo/
$ find . -maxdepth 2 | xargs grep -n "\.system\b" || true
$ find . -maxdepth 2 | xargs grep -n "\.popen\b" || true
$ find . -maxdepth 2 | xargs grep -n "sh -c" || true
$ find . -maxdepth 2 | xargs grep -n "\`" || true
$ grep -RIn "os\.system" /workspace/repo/ | head -n 200
$ find . -maxdepth 2 | xargs grep -n "sh -c" || true
$ grep -RIn "subprocess" /workspace/repo/ | head -n 200
$ grep -RIn "os\.system" /workspace/repo/
$ grep -RIn "os\.popen" /workspace/repo/
$ grep -RIn "sh -c" /workspace/repo/
$ grep -RIn "\`" /workspace/repo/
$ grep -RIn "os\.system" /workspace/repo/src/
$ sed -n '750,850p' /workspace/repo/src/bin/gate_runner.rs
```
