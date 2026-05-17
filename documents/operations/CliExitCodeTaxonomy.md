# CLI exit-code taxonomy

Every `rustynet*` binary follows the shared `rustynetd::exit_codes::ExitCode`
taxonomy. Shells, CI retry loops, and `systemd`
`RestartPreventExitStatus=` lists can branch on the numeric code
without parsing error text.

## Reviewed taxonomy

| Code | Label              | Meaning                                                        |
|------|--------------------|----------------------------------------------------------------|
| 0    | `success`          | the command did what was asked                                 |
| 1    | `generic_failure`  | last-resort fallback when no narrower code fits                |
| 64   | `bad_args`         | invalid argv / missing required flag / unknown subcommand      |
| 65   | `config_error`     | configuration on disk failed validation (bad path, bad schema) |
| 70   | `transient_failure`| IO / network / retry-safe failure                              |
| 78   | `policy_reject`    | fail-closed policy or signed-state gate rejected the operation |

The numeric codes align with BSD `sysexits.h`
(`EX_USAGE=64`, `EX_DATAERR=65`, `EX_SOFTWARE=70`, `EX_CONFIG=78`) so
existing wrappers that already understand sysexits work without
Rustynet-specific knowledge.

## Operator decision rules

* **0** — operation succeeded. No action needed.
* **1** — fallback `generic_failure`. The CLI did not classify the
  error into a narrower bucket. Treat as `transient_failure` for retry
  decisions only if the error message clearly names an IO/network
  cause; otherwise treat as `policy_reject` and escalate.
* **64** — bad CLI args. Re-run with `--help`. Never retry the same
  argv unchanged.
* **65** — config error. The on-disk configuration named in the error
  message failed validation. Fix the file (or the path it points at)
  before re-running.
* **70** — transient failure. The error message names a retry-safe
  cause (TCP RST, EOF, DNS lookup failure, helper-socket connection
  refused before the daemon was ready). Retry is sane; CI loops may
  retry up to a bounded count.
* **78** — policy reject. A fail-closed gate (signature verification,
  reviewed-root check, runtime-ACL drift, plaintext-key-at-rest)
  refused the operation. **DO NOT retry**. Operator must inspect the
  named drift and resolve it before re-running.

## CI retry contract

CI loops that retry on transient failures **must** scope retries to
exit code 70 alone. Retrying on 78 risks suppressing a real
fail-closed reject; retrying on 64 / 65 just wastes cycles because the
input or config is broken.

```bash
attempt=0
until rustynet ops some-step; do
  rc=$?
  case "$rc" in
    70) attempt=$((attempt + 1)); [ "$attempt" -gt 5 ] && exit "$rc"; sleep 5 ;;
    *)  exit "$rc" ;;  # do not retry non-transient failures
  esac
done
```

## systemd integration

`rustynetd.service` already sets `Restart=on-failure`. To prevent
systemd from masking a fail-closed reject as a retryable crash, the
unit should pin:

```ini
RestartPreventExitStatus=64 65 78
```

so the daemon stops cleanly on bad args, config errors, and policy
rejects, leaving the operator to fix the underlying state before
re-enabling.

## CLI surface coverage

The taxonomy is enforced at the two top-level entry points plus every
ancillary binary:

* `crates/rustynetd/src/main.rs` — `classify_top_level_error` maps the
  daemon's startup-error strings to the taxonomy.
* `crates/rustynet-cli/src/main.rs` — `classify_cli_error` maps the
  `execute()` result strings.
* All 72 binaries under `crates/rustynet-cli/src/bin/` — each imports
  `rustynetd::exit_codes::ExitCode` and routes its failure shapes
  through the taxonomy. Phase-gate wrappers and cargo-spawn helpers
  map repo-root / argv failures to `ConfigError(65)` and subprocess
  spawn failures to `TransientFailure(70)`; security-sensitive gates
  (tamper, attestation, integrity, drift, signature mismatch, hardened
  install) map fail-closed verdicts to `PolicyReject(78)` instead of
  passing them through as a retryable generic failure. Subprocess exit
  codes pass through unchanged so an inner CLI's taxonomy verdict
  survives the outer wrapper.

Operators can rely on the numeric code from any `rustynet*` binary —
there are no legacy `exit(1)`-only paths left in production wrappers.

## Adding new variants

The taxonomy is intentionally narrow. Add a new variant only when:

1. an existing variant would silently mask a meaningfully different
   operator response (e.g. retry vs no-retry),
2. the new variant has a clear `operator_hint`, and
3. the numeric code does not collide with any existing variant and
   ideally matches a `sysexits.h` value.

Bump the snapshot test
`reviewed_taxonomy_pinned_at_six_variants` in
`crates/rustynetd/src/exit_codes.rs` and add a paired commit-message
explanation when raising the variant count.
