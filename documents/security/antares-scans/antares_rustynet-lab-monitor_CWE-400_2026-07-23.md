# Antares scan — `rustynet-lab-monitor` — CWE-400

**Date:** 2026-07-23  
**Scope:** `rustynet-lab-monitor` (34 first-party `.rs` files)  
**CWE:** CWE-400 — Uncontrolled resource consumption: resources (CPU, memory, connections, buffers) are not bounded, enabling resource-exhaustion / DoS.  
**Verdict:** `vulnerable_files`  
**Budget:** 12/22 terminal cmds, 18 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/control/launcher.rs` | inspected |

## Model reasoning

The orchestrator spawning logic in src/control/launcher.rs spawns an orchestrator process for each monitor job without any limit on the number of concurrent or total spawned processes. The spawn_orchestrator function constructs a unique job_id and creates a dedicated report directory and job directory per invocation, then calls tokio::process::Command::new(...).args(&args).spawn(), with no cap on how many jobs can be spawned concurrently. This can lead to uncontrolled resource consumption (CPU, memory, open files, network connections) and potential DoS when many monitor jobs are processed.

## Commands run
```
$ ls -la /workspace/repo/
$ find /workspace/repo -maxdepth 2 | head -n 100
$ grep -R "spawn\(|tokio::spawn|spawn_sync|thread::spawn|std::thread::spawn" -n /workspace/repo/src || true
$ grep -R "spawn" -n /workspace/repo/src | head -n 200
$ sed -n '2100,2180p' src/app.rs
$ sed -n '23200,23280p' src/app.rs
$ wc -l src/app.rs
$ sed -n '23200,23260p' src/app.rs
$ grep -R "spawn_orchestrator" -n src || true
$ grep -R "spawn_orchestrator" src/ || true
$ sed -n '1,240p' src/control/launcher.rs
$ sed -n '210,260p' src/control/launcher.rs
$ grep -R "OPENCODE_MAIN_MODEL" -n || true
$ grep -R "OPENCODE_MAIN_MODEL" . || true
$ grep -R "OPENCODE_MAIN_MODEL" src/
$ ls -la fixtures/
$ grep -R "spawn_orchestrator" -n .. | head -n 200
```
