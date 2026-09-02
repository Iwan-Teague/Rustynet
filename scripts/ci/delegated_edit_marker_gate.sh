#!/usr/bin/env bash
# Delegated-edit marker gate (QH-26 item 4): dispatches to the Rust
# implementation `check_delegated_edit_markers` in rustynet-cli.
# Environment knobs (documented in the binary's header):
#   MARKER_SCAN_DEPTH  - git log window depth (default 200)
#   MARKER_SCAN_TIP    - tip ref to scan (default HEAD)
#   MARKER_ALLOWLIST   - extra allowlist SHAs/prefixes, comma-separated
#                        (deliberate post-hoc rescue only; prefer editing
#                        the const table in the binary)
set -euo pipefail
exec cargo run --quiet -p rustynet-cli --bin check_delegated_edit_markers -- "$@"
