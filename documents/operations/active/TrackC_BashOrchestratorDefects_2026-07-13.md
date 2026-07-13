# Track-C Bash-Orchestrator Defect Log — 2026-07-13

The W5.7 plan retires the legacy bash orchestrator
(`scripts/e2e/live_linux_lab_orchestrator.sh`). Track C pairs it against the
Rust `--node` engine per the §0.a functional-parity spec. Per owner decision
(2026-07-13): **document the legacy path's defects and form pairs only on
topologies bash handles cleanly** — do NOT invest in fixing the path being
removed. A bash defect where Rust is correct is evidence the Rust engine is
at-or-better, which supports the retirement; it is recorded here, not patched.

Every claim below is first-hand from a live run.

## BASH-DEF-1 — role collocation: one node bootstrapped under two roles

**Run:** `state/bash-baseline-1783932078` (commit `cf904d7`, invoked
`--exit-vm debian-headless-2 --client-vm debian-headless-4 --legacy-bash-orchestrator`).

**Observed.** The bash orchestrator bootstrapped `debian-headless-4` (192.168.64.10)
**twice** — once as `client-1` (client) and once as `client-3` (aux):
```
e2e bootstrap host complete: role=client node_id=client-3 src_dir=/home/debian/Rustynet   # aux slot, same guest
```
It pulled `debian-headless-4` into the `aux` slot because that guest's inventory
`lab_role` is `aux`, even though it was ALSO the explicit `--client-vm`. The
Rust `--node` engine takes roles only from the explicit `--node alias:role`
pairs and never auto-expands from `lab_role`, so it ran a clean 2-node
exit+client topology on the same flags. **Rust-correct, bash-defective** (a
node should not be admitted under two roles; the resolver should dedup or
reject).

## BASH-DEF-2 — dns-zone pubkey staging race on collocated roles

**Downstream of BASH-DEF-1.** With `client-1` and `client-3` on the SAME guest,
the `refresh_dns_zone_before_validate` step raced on a shared per-host staging
path and the aux pass failed:
```
[parallel:refresh_dns_zone_before_validate] aux debian@192.168.64.10 rc=1
install: cannot stat '/tmp/rn-dns-zone.pub': No such file or directory
```
`/tmp/rn-dns-zone.pub` is a fixed host-global temp path; two roles on one guest
clobber/miss it. This fail-closed `validate_baseline_runtime` (rc=1) — the ONLY
stage the bash run failed; every setup stage through `enforce_baseline_runtime`
passed. The Rust engine writes per-node collision-free staging
(`write_secure_temp_file`, RNQ-18) and passed `validate_baseline_runtime` on the
paired topology.

## Parity implication

The bash `validate_baseline_runtime` failure is NOT a Rust regression — it is
BASH-DEF-1/2, i.e. the legacy path mis-resolving the topology and racing its own
temp file. A pair on this exact invocation cannot reach
`overall_functional_parity_pass=true` (the shared `validate_baseline_runtime`
diverges: bash=fail, rust=pass) — but the divergence is a documented bash defect,
recorded here as evidence FOR retirement, not against the Rust engine.

## "Pair where clean" remediation (config, not bash-code)

`debian-headless-4`'s inventory `lab_role` was the stale/inaccurate `aux`
(it is the client in every Rust run, and debian-headless-2's was the equally
inaccurate `client` while it serves as exit). Correcting `debian-headless-4`
`lab_role` → `client` removes the bash aux-auto-pull, so bash resolves a clean
2-node exit+client topology matching the Rust `--node` run — a legitimate
inventory correction, not a patch to the retiring bash code. The paired
bash↔Rust run is then formed at a single shared commit with a clean tree per
§0.a (G5). BASH-DEF-1/2 remain documented defects of the legacy path.
