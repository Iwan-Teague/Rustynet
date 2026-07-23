# Antares-1B operating guide (Rustynet)

_Living document — regenerated after every campaign run. 88 runs logged so far._

## What this agent is
Cisco **Antares-1B** is a vulnerability-**localization** model: given one CWE class
and read-only shell access, it explores a repo (grep/find/cat) under a command
budget and submits a ranked list of candidate files — or aborts. It **does not**
confirm exploitability, explain the flaw, or write fixes. Everything it emits is a
**triage lead**, not a finding.

## How to read the metrics
Without ground truth we use behavioural proxies for quality:
- **inspected-ratio** — fraction of submitted files the model actually *opened*
  (cat/head/sed) vs. submitted from a grep hit alone. Higher = less hallucination.
- **abort %** — runs that burned the budget with no submission.
- **distraction cmds** — commands matching wrong-language idioms (JS/Python:
  `Math.random`, `package.json`, `os.system`, …). High = model off in the weeds.
- **fabricated files** — paths the model tried to submit that **do not exist** in
  the repo. The harness existence-checks every submission, bounces invented paths
  back to the model to correct (up to twice), and drops any that remain — so
  fabricated paths never reach a report as a "finding." A high count here means the
  model was guessing paths rather than verifying them.

## Qualitative findings (from observed runs)
- **Tight scope beats whole-repo.** On the full tree the model wastes budget on
  broad greps and wrong-language patterns and submits files it never opened. Scoped
  to one crate it reads what it submits.
- **Domain-word collisions mislead it.** For CWE-22 (path traversal) it keyword-
  matched Rustynet's "traversal" (NAT traversal) — a false lead. Watch any CWE whose
  name collides with domain vocabulary.
- **Off-target CWEs still get a confident answer.** Rustynet is WireGuard (static
  keys, no TLS/X.509), yet CWE-295 still returned files. A non-empty verdict is not
  evidence the vuln class even applies.
- **Wrong-language muscle memory.** It reaches for Node/Python idioms first; on a
  Rust repo that's pure budget waste (see distraction metric).

## Data-driven envelope
### By scope size

| scope size | Runs | Abort% | Avg inspected-ratio | Runs w/ >=1 inspected | Avg fabricated files | Avg distraction cmds |
|---|---|---|---|---|---|---|
| single-file | 18 | 17% | 0.58 | 39% | 0.0 | 0.2 |
| small(2-10) | 34 | 26% | 0.65 | 44% | 0.0 | 0.1 |
| medium(11-40) | 18 | 6% | 0.71 | 78% | 0.0 | 0.0 |
| whole-repo(120+) | 18 | 6% | 0.62 | 56% | 0.0 | 0.0 |

### By CWE class

| CWE class | Runs | Abort% | Avg inspected-ratio | Runs w/ >=1 inspected | Avg fabricated files | Avg distraction cmds |
|---|---|---|---|---|---|---|
| CWE-78 | 14 | 43% | 0.68 | 43% | 0.0 | 0.4 |
| CWE-22 | 14 | 7% | 0.73 | 57% | 0.0 | 0.0 |
| CWE-20 | 14 | 21% | 0.68 | 57% | 0.0 | 0.0 |
| CWE-400 | 14 | 0% | 0.41 | 43% | 0.0 | 0.0 |
| CWE-862 | 13 | 31% | 0.64 | 38% | 0.0 | 0.0 |
| CWE-327 | 13 | 0% | 0.77 | 69% | 0.0 | 0.0 |
| CWE-200 | 1 | 0% | 0.00 | 0% | 0.0 | 0.0 |
| CWE-798 | 1 | 0% | 1.00 | 100% | 0.0 | 0.0 |
| CWE-330 | 1 | 0% | 0.00 | 0% | 0.0 | 0.0 |
| CWE-295 | 1 | 0% | 1.00 | 100% | 0.0 | 0.0 |
| CWE-502 | 1 | 0% | 1.00 | 100% | 0.0 | 0.0 |
| CWE-918 | 1 | 0% | 1.00 | 100% | 0.0 | 0.0 |

### Highest-signal runs so far (read what they submitted)

| Scope | CWE | Files | Inspected/Submitted | Distraction |
|---|---|---|---|---|
| ALL | CWE-20 | 498 | 1/1 | 0 |
| ALL | CWE-862 | 498 | 1/1 | 0 |
| ALL | CWE-798 | 498 | 1/1 | 0 |
| ALL | CWE-295 | 498 | 1/1 | 0 |
| ALL | CWE-502 | 498 | 1/1 | 0 |
| ALL | CWE-918 | 498 | 1/1 | 0 |
| rustynet-advisor | CWE-327 | 2 | 1/1 | 0 |
| rustynet-backend-api | CWE-22 | 3 | 1/1 | 0 |

## Recommendation
Use Antares only as a **scoped** triage step: point it at a single crate/subsystem, pick a CWE that plausibly applies, and treat an `inspected` submission as a lead for a code-grounded review. Ignore whole-repo runs and off-domain CWEs. Confirm every lead with a real reviewer or a coding model.
