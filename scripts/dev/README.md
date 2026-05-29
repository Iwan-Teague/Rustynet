# scripts/dev — local developer tooling

Helpers for working on the repo locally. Not part of any shipped artifact and
not invoked by CI gates.

## cargo_watchdog.sh

Runs a long build/test command but **fails fast and loudly** instead of hanging
forever. It exists because a backgrounded `cargo` can wedge in ways that never
produce a completion signal:

- **Full disk** — cargo blocks/errors writing artifacts; the process sits at 0%
  CPU and is indistinguishable from one doing work.
- **`target/` build-lock contention** — a second `cargo` run (or a leftover one)
  holds the lock; the new run waits indefinitely.
- **`cargo ... | tail`** — piping through `tail` discards cargo's exit code (you
  get `tail`'s `0`) and all but the last lines of output, so a failure looks like
  a pass.

The watchdog turns each of these into a prompt, explicit exit, so the caller's
normal completion notification fires. It runs the command directly (no `tail`
pipe), tees full output to a log, and **exits with the command's real status**.

```sh
scripts/dev/cargo_watchdog.sh -- \
  cargo test -p rustynet-cli --bin rustynet-cli vm_lab::orchestrator
```

Exit codes: the wrapped command's own code on completion; `28` on a disk-space
abort; `124` on stall or wall-clock timeout.

Env knobs: `WATCHDOG_STALL_SECS` (default 240), `WATCHDOG_MAX_SECS` (2400),
`WATCHDOG_POLL_SECS` (15), `WATCHDOG_MIN_FREE_GIB` (5), `WATCHDOG_LOG`.

### Build/test hygiene notes

- Prefer `--bin rustynet-cli` over `--bins` when exercising `vm_lab` unit tests:
  `vm_lab` is compiled only into the main `rustynet-cli` binary (`src/main.rs`),
  so `--bins` needlessly rebuilds ~50 other binaries.
- Never run a second `cargo` build/test while one is in flight on the same
  `target/` — they serialize on the build lock and can wedge each other.
- Watch free disk: a full `Data` volume is the most common cause of an
  invisible build wedge in this workspace (`target/` is tens of GiB).
