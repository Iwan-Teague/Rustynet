#!/usr/bin/env bash
# Install the Rustynet MCP servers for agent access.
#
# Usage:
#   ./scripts/mcp/install.sh                 # debug build → ./bin, print configs
#   ./scripts/mcp/install.sh --release       # release build → ./bin
#   ./scripts/mcp/install.sh --print-configs # only print config snippets
#
# Builds the three server binaries and copies them to ./bin (repo-local,
# gitignored — this is what the committed .zed/settings.json references). The
# repo root is baked into each binary at compile time (build.rs), so the
# servers work regardless of the client's working directory.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN_DIR="${REPO_ROOT}/bin"
RELEASE_FLAG=""
PROFILE_DIR="debug"
PRINT_ONLY=false

for arg in "$@"; do
    case "$arg" in
        --release) RELEASE_FLAG="--release"; PROFILE_DIR="release" ;;
        --print-configs) PRINT_ONLY=true ;;
        *) echo "Unknown arg: $arg"; exit 1 ;;
    esac
done

BINARIES=(rustynet-mcp-repo-context rustynet-mcp-gate-runner rustynet-mcp-lab-state)

if [ "$PRINT_ONLY" = false ]; then
    echo "==> Building MCP server binaries..."
    ( cd "$REPO_ROOT" && cargo build -p rustynet-mcp $RELEASE_FLAG )

    mkdir -p "$BIN_DIR"
    for bin in "${BINARIES[@]}"; do
        SRC="${REPO_ROOT}/target/${PROFILE_DIR}/${bin}"
        DST="${BIN_DIR}/${bin}"
        if [ -f "$SRC" ]; then
            cp "$SRC" "$DST"
            chmod 755 "$DST"
            # On Apple Silicon, copying a Mach-O invalidates its code signature
            # and the kernel SIGKILLs it on exec. Re-sign ad-hoc after copy.
            if [ "$(uname -s)" = "Darwin" ] && command -v codesign >/dev/null 2>&1; then
                codesign --force --sign - "$DST" >/dev/null 2>&1 || \
                    echo "  WARNING: codesign failed for $DST (may be SIGKILLed on exec)"
            fi
            echo "  installed: $DST"
        else
            echo "  WARNING: binary not found at $SRC"
        fi
    done
    echo ""
    echo "==> MCP servers installed to $BIN_DIR"
    echo ""
fi

RC="${BIN_DIR}/rustynet-mcp-repo-context"
GR="${BIN_DIR}/rustynet-mcp-gate-runner"
LS="${BIN_DIR}/rustynet-mcp-lab-state"

cat <<EOF
========================================
 Zed (.zed/settings.json or global settings)
========================================
{
  "context_servers": {
    "rustynet-repo-context": { "command": "${RC}", "args": [], "env": {} },
    "rustynet-gate-runner":  { "command": "${GR}", "args": [], "env": {} },
    "rustynet-lab-state":    { "command": "${LS}", "args": [], "env": {} }
  }
}

========================================
 Claude Desktop (macOS)
 ~/Library/Application Support/Claude/claude_desktop_config.json
========================================
{
  "mcpServers": {
    "rustynet-repo-context": { "command": "${RC}" },
    "rustynet-gate-runner":  { "command": "${GR}" },
    "rustynet-lab-state":    { "command": "${LS}" }
  }
}

========================================
 VS Code / Cursor (.vscode/mcp.json)
========================================
{
  "servers": {
    "rustynet-repo-context": { "command": "${RC}" },
    "rustynet-gate-runner":  { "command": "${GR}" },
    "rustynet-lab-state":    { "command": "${LS}" }
  }
}

========================================
 Servers
========================================
  rustynet-mcp-repo-context  — 17 tools + resources (docs) + prompts
                               (read-order, requirements, security controls/findings,
                                architecture constraints, role transitions, platform
                                support, crate structure, which_crate boundary rules,
                                get_crate_dependencies blast-radius, doc search/list/read).
  rustynet-mcp-gate-runner   — 11 tools (fmt/check/clippy/test/build, security audit,
                                run_security_gates bundled security suite, categorized
                                CI gate scripts + run_gate_scripts batch) — all
                                kill-on-timeout.
  rustynet-mcp-lab-state     — 42 tools + overnight-loop prompt. UTM discovery/
                                inventory/restart/recover, power on/off + state, host disk,
                                out-of-band guest net diagnostics (get_vm_network_info),
                                one-call readiness (preflight_check), deploy preview
                                (what_will_deploy), sync/bootstrap/diagnostics, AND the
                                autonomous overnight loop: async background live-lab runs
                                (start_live_lab_run with auto-topology → wait_for_job →
                                get_run_result → explain_stage → get_stage_log /
                                grep_report / read_report_artifact), get_run_trend,
                                diff_runs (helped vs regressed), a durable loop journal
                                (write_loop_note / get_loop_journal) that survives context
                                compaction, prune_jobs, run matrix. Built for unattended
                                24h+ loops.

The repo root is baked into each binary (build.rs); no working_directory needed.
Override with RUSTYNET_REPO_ROOT if running a binary built from a different checkout.
EOF
