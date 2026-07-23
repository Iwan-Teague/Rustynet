# Antares scan — `rustynet-control` — CWE-20

**Date:** 2026-07-23  
**Scope:** `rustynet-control` (16 first-party `.rs` files)  
**CWE:** CWE-20 — Improper input validation: input is not validated (or is validated incorrectly) before use, allowing malformed or malicious data to alter control/data flow.  
**Verdict:** `vulnerable_files`  
**Budget:** 18/22 terminal cmds, 19 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/scale.rs` | inspected |
| `src/lib.rs` | inferred (grep-only) |

## Model reasoning

The ControlPlane implementation handles remote control plane endpoints and performs validation/decoding of relay fleet wire formats. In src/scale.rs, the ControlPlaneReplica struct and elect_active logic interact with control-plane replicas, and the relay fleet wire parsing logic is likely implemented in src/lib.rs. These areas are prime candidates for CWE-20 issues: improper validation or parsing of remote endpoint URLs/relay fleet wire structures could allow malformed or malicious data to alter control/data flow. The scale.rs file contains logic that trusts control-plane replica endpoints (using issuer/url checks), and the lib.rs file likely contains the relay fleet wire parsing code that must validate input structures before use.

## Commands run
```
$ find . -maxdepth 2 | head -n 100
$ grep -R "url" -n . | head -n 200
$ grep -R "http" -n . | head -n 200
$ cat Cargo.toml
$ grep -R "tokio::sync::mpsc" -n .
$ grep -R "Client" -n src | head -n 200
$ grep -R "http" src | head -n 200
$ grep -R "url\." -n . | head -n 200
$ grep -R "ClientConfig" -n . | head -n 200
$ cat src/scale.rs
$ grep -R "ControlPlaneConfig" -n . | head -n 200
$ grep -R "ControlPlane" -n . | head -n 200
$ grep -R "ControlPlane" src/ | head -n 200
$ grep -R "ControlPlane" . | grep -n "ControlPlaneConfig"
$ grep -R "ControlPlaneConfig" . | head -n 200
$ grep -R "ControlPlane" . | head -n 300 | tail -n 100
$ find . -type d | grep -i "rustynet-"
$ ls -la
```
