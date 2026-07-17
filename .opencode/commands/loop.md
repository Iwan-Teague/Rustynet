---
description: Start or prepare the Rustynet unattended live-lab loop
---

# Rustynet `/loop`

Run the OpenCode-backed Rustynet live-lab loop. This command is a UX wrapper;
the durable state machine lives in `scripts/loop/opencode_loop.sh`.

Use the arguments below as the target area and selectors:

```text
$ARGUMENTS
```

If no arguments are provided, show the usage:

```bash
./scripts/loop/opencode_loop.sh --help
```

If arguments are provided, start the loop:

```bash
./scripts/loop/opencode_loop.sh start $ARGUMENTS
```

Important rules:
- Use `triage_on_failure=false`; OpenCode Flash report review handles summarizing.
- Main OpenCode v4-pro agent patches, gates, commits, then launches the next focused `ai_lab_run`.
- Do not ask the user for confirmation.
