# Antares scan — `rustynet-cli` — CWE-400

**Date:** 2026-07-23  
**Scope:** `rustynet-cli` (273 first-party `.rs` files)  
**CWE:** CWE-400 — Uncontrolled resource consumption: resources (CPU, memory, connections, buffers) are not bounded, enabling resource-exhaustion / DoS.  
**Verdict:** `vulnerable_files`  
**Budget:** 12/30 terminal cmds, 17 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/live_lab_stage_manifest.rs` | inspected |

## Model reasoning

The file reads a previously emitted `stage_manifest.json.tmp` file into memory and serializes it (serde_json::to_string_pretty) before writing it to disk. This can consume unbounded memory if the manifest file is very large, enabling resource exhaustion (CWE-400). The code performs `serde_json::to_string_pretty(manifest) ... fs::write(...)` and then `fs::rename(...)` the generated string into a file, without any size limits or streaming/progressive processing.

## Commands run
```
$ ls -la /workspace/repo/
$ find /workspace/repo -maxdepth 2 | head -n 80
$ grep -RIn "read_full\|read_to_string\|read_to_vec\|Vec::with_capacity\|Vec::reserve\|Vec::resize\|thread::spawn\|tokio::spawn\|spawn_future\|spawn\|accept\|TcpListener::new\|TcpStream::new\|incoming_channel\|for incoming in accept\|read_some_data\|read_some_data_async\|read_to_string_async\|read_full_async\|unbounded_channel\|unbounded_box_channel\|buffer_from_bytes\|Vec::from_raw_parts\|Vec::from_raw_parts_mut\|Vec::from_capacity" /workspace/repo/
$ grep -RIn "read_full" /workspace/repo/
$ grep -RIn "read_to_string" /workspace/repo/
$ grep -RIn "BufReader::new" /workspace/repo/
$ grep -RIn "read_to_string(" /workspace/repo/
$ grep -RIn "read_full(" /workspace/repo/
$ grep -RIn "read_to_string_async" /workspace/repo/
$ grep -RIn "BufRead" /workspace/repo/
$ grep -RIn "BufReader::new(" /workspace/repo/
$ cat src/live_lab_stage_manifest.rs
$ sed -n '240,270p' src/live_lab_stage_manifest.rs
$ find . -name "*.rs" | xargs grep -n "manifest" | head -n 50
$ grep -RIn "manifest" . | grep -i "stage" || true
$ grep -RIn "manifest" . | grep -i "stage" || true
```
