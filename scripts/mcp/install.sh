#!/usr/bin/env bash
# Install the Rustynet MCP servers for agent access.
#
# Usage:
#   ./scripts/mcp/install.sh                 # debug build → ./bin, print configs
#   ./scripts/mcp/install.sh --release       # release build → ./bin
#   ./scripts/mcp/install.sh --print-configs # only print config snippets
#
# Builds the four server binaries and copies them to ./bin (repo-local,
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

BINARIES=(rustynet-mcp-repo-context rustynet-mcp-gate-runner rustynet-mcp-lab-state rustynet-mcp-ai-agent)

if [ "$PRINT_ONLY" = false ]; then
    echo "==> Building MCP server binaries..."
    ( cd "$REPO_ROOT" && cargo build -p rustynet-mcp $RELEASE_FLAG )

    mkdir -p "$BIN_DIR"
    for bin in "${BINARIES[@]}"; do
        SRC="${REPO_ROOT}/target/${PROFILE_DIR}/${bin}"
        DST="${BIN_DIR}/${bin}"
        if [ -f "$SRC" ]; then
            # Atomic install: a plain in-place cp TRUNCATES a binary the MCP
            # client still has mmap'd (symptom: the server starts but emits
            # nothing). Stage next to the destination, sign, then mv -f.
            cp "$SRC" "${DST}.new"
            chmod 755 "${DST}.new"
            # On Apple Silicon, copying a Mach-O invalidates its code signature
            # and the kernel SIGKILLs it on exec. Re-sign ad-hoc after copy.
            if [ "$(uname -s)" = "Darwin" ] && command -v codesign >/dev/null 2>&1; then
                codesign --force --sign - "${DST}.new" >/dev/null 2>&1 || \
                    echo "  WARNING: codesign failed for ${DST}.new (may be SIGKILLed on exec)"
            fi
            mv -f "${DST}.new" "$DST"
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
AA="${BIN_DIR}/rustynet-mcp-ai-agent-launcher.sh"

cat <<EOF
========================================
 Zed (.zed/settings.json or global settings)
========================================
{
  "context_servers": {
    "rustynet-repo-context": { "command": "${RC}", "args": [], "env": {} },
    "rustynet-gate-runner":  { "command": "${GR}", "args": [], "env": {} },
    "rustynet-lab-state":    { "command": "${LS}", "args": [], "env": {} },
    "rustynet-ai-agent":     { "command": "${AA}", "args": [], "env": {} }
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
    "rustynet-lab-state":    { "command": "${LS}" },
    "rustynet-ai-agent":     { "command": "${AA}" }
  }
}

========================================
 VS Code / Cursor (.vscode/mcp.json)
========================================
{
  "servers": {
    "rustynet-repo-context": { "command": "${RC}" },
    "rustynet-gate-runner":  { "command": "${GR}" },
    "rustynet-lab-state":    { "command": "${LS}" },
    "rustynet-ai-agent":     { "command": "${AA}" }
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
  rustynet-mcp-ai-agent      — 14 tools. Research/triage/run-driver layer calling whichever
                                LLM provider is configured (DeepSeek default; Grok/Kimi/GLM/
                                Qwen built in; any other OpenAI-Chat-Completions-compatible
                                provider via a registry file — see CLAUDE.md/AGENTS.md
                                §12.5). ai_lab_run/ai_live_lab drive + triage the live lab;
                                ai_agent is a grounded read-only research agent; ai_read/
                                ai_write/ai_read_write are paste-in-context proxies;
                                ai_list_models/ai_check_balance are read-only discovery.

The repo root is baked into each binary (build.rs); no working_directory needed.
Override with RUSTYNET_REPO_ROOT if running a binary built from a different checkout.

The printed configs above point rustynet-ai-agent at the LAUNCHER script
(${AA}), not the raw binary — the launcher reads each
provider's API key from macOS Keychain and exports it before exec'ing the
real binary (CLAUDE.md/AGENTS.md §12.5). This install script builds and
atomically installs the raw binary only; the launcher is a small,
hand-authored, gitignored wrapper that must already exist at that path (or
be recreated) for the printed configs to work — it does not itself need
rebuilding when the binary changes.

========================================
 IMPORTANT: reconnect after reinstalling
========================================
MCP clients spawn the server ONCE and keep that process for the session, so a
freshly installed ./bin is NOT picked up until you reconnect — restart the
editor / "Reconnect MCP server", or in Claude Code reconnect the server. A
session left running on the old binary keeps the old tool set.

Each server now reports its build provenance as serverInfo.version, e.g.
  "0.1.0 (git 1c9f306abcde-dirty, built 2026-06-09T14:03:11Z)"
If that git SHA lags \`git rev-parse --short=12 HEAD\`, the running process is
stale — reinstall and reconnect. A \`-dirty\` suffix means it was built from a
modified working tree.
EOF
