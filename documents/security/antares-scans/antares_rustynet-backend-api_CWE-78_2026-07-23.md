# Antares scan — `rustynet-backend-api` — CWE-78

**Date:** 2026-07-23  
**Scope:** `rustynet-backend-api` (3 first-party `.rs` files)  
**CWE:** CWE-78 — OS command injection: externally-influenced input is incorporated into an OS command (sh -c, Command args) without neutralization.  
**Verdict:** `vulnerable_files`  
**Budget:** 6/15 terminal cmds, 19 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/lib.rs` | inspected |

## Model reasoning

The repository contains a single source file (src/lib.rs) that implements the transport backend logic. The relevant implementation likely constructs or invokes OS network/transport operations using raw socket creation or binding, which can be influenced by external input. If this file contains code that builds socket options or creates/binds sockets from externally-supplied addresses/ports, it is likely to incorporate externally-influenced input into OS command-like operations (OS socket creation/binding), matching the CWE-78 pattern. The file is the primary candidate for the vulnerability.

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
$ grep -RIn "sh -c" src/ || true
$ grep -RIn "\`\`" src/ || true
$ grep -RIn "Command::new\(" src/lib.rs || true
$ cat src/lib.rs
$ grep -RIn "TunnelBackend\|backend\.|Backend\.|start\(" src/lib.rs | head -n 200
$ grep -RIn "start\(" src/lib.rs | head -n 200
$ sed -n '300,500p' src/lib.rs
$ grep -RIn "Command::new\(" src/lib.rs | head -n 200
```
