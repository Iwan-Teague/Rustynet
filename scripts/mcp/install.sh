#!/usr/bin/env bash
# Install Rustynet MCP servers for global agent access.
#
# Usage:
#   ./scripts/mcp/install.sh                 # Debug build, register locally
#   ./scripts/mcp/install.sh --release       # Release build, register globally
#   ./scripts/mcp/install.sh --print-configs # Only print config snippets
#
# This script:
# 1. Builds the three MCP server binaries
# 2. Copies them to a stable location (~/.local/bin or /usr/local/bin)
# 3. Prints configuration snippets for each supported platform
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_DIR="${HOME}/.local/bin"
RELEASE_FLAG=""
PRINT_ONLY=false

for arg in "$@"; do
    case "$arg" in
        --release) RELEASE_FLAG="--release" ;;
        --print-configs) PRINT_ONLY=true ;;
        *) echo "Unknown arg: $arg"; exit 1 ;;
    esac
done

if [ "$PRINT_ONLY" = false ]; then
    echo "==> Building MCP server binaries..."
    cd "$REPO_ROOT"
    cargo build -p rustynet-mcp $RELEASE_FLAG

    PROFILE_DIR="debug"
    [ -n "$RELEASE_FLAG" ] && PROFILE_DIR="release"

    mkdir -p "$INSTALL_DIR"

    for bin in rustynet-mcp-repo-context rustynet-mcp-gate-runner rustynet-mcp-lab-state; do
        SRC="target/$PROFILE_DIR/$bin"
        DST="$INSTALL_DIR/$bin"
        if [ -f "$SRC" ]; then
            cp "$SRC" "$DST"
            chmod 755 "$DST"
            echo "  installed: $DST"
        else
            echo "  WARNING: binary not found at $SRC"
        fi
    done

    echo ""
    echo "==> MCP servers installed to $INSTALL_DIR"
    echo ""
fi

# ── Print configuration snippets ────────────────────────────────────

cat << 'ZEDCONFIG'
========================================
 Zed (.zed/settings.json or global settings)
========================================

Add to your Zed settings:

{
  "context_servers": {
    "rustynet-repo-context": {
      "command": {
        "path": "ZEDCONFIG
echo -n "        \"$INSTALL_DIR/rustynet-mcp-repo-context\""
cat << 'ZEDCONFIG2'
"
      },
      "working_directory": "ZEDCONFIG2
echo -n "        \"$REPO_ROOT\""
cat << 'ZEDCONFIG3'
"
    },
    "rustynet-gate-runner": {
      "command": {
        "path": "ZEDCONFIG3
echo -n "        \"$INSTALL_DIR/rustynet-mcp-gate-runner\""
cat << 'ZEDCONFIG4'
"
      },
      "working_directory": "ZEDCONFIG4
echo -n "        \"$REPO_ROOT\""
cat << 'ZEDCONFIG5'
"
    },
    "rustynet-lab-state": {
      "command": {
        "path": "ZEDCONFIG5
echo -n "        \"$INSTALL_DIR/rustynet-mcp-lab-state\""
cat << 'ZEDCONFIG6'
"
      },
      "working_directory": "ZEDCONFIG6
echo -n "        \"$REPO_ROOT\""
cat << 'ZEDCONFIG7'
"
    }
  }
}

========================================
 Claude Desktop (macOS)
========================================

Edit: ~/Library/Application Support/Claude/claude_desktop_config.json

{
  "mcpServers": {
    "rustynet-repo-context": {
      "command": "ZEDCONFIG7
echo -n "\"$INSTALL_DIR/rustynet-mcp-repo-context\""
cat << 'CLAUDECONFIG'
",
      "cwd": "CLAUDECONFIG
echo -n "\"$REPO_ROOT\""
cat << 'CLAUDECONFIG2'
"
    },
    "rustynet-gate-runner": {
      "command": "CLAUDECONFIG2
echo -n "\"$INSTALL_DIR/rustynet-mcp-gate-runner\""
cat << 'CLAUDECONFIG3'
",
      "cwd": "CLAUDECONFIG3
echo -n "\"$REPO_ROOT\""
cat << 'CLAUDECONFIG4'
"
    },
    "rustynet-lab-state": {
      "command": "CLAUDECONFIG4
echo -n "\"$INSTALL_DIR/rustynet-mcp-lab-state\""
cat << 'CLAUDECONFIG5'
",
      "cwd": "CLAUDECONFIG5
echo -n "\"$REPO_ROOT\""
cat << 'CLAUDECONFIG6'
"
    }
  }
}

========================================
 VS Code / Cursor (with MCP extension)
========================================

Create .vscode/mcp.json in the project root:

{
  "servers": {
    "rustynet-repo-context": {
      "command": "CLAUDECONFIG6
echo -n "\"$INSTALL_DIR/rustynet-mcp-repo-context\""
cat << 'VSCODECONFIG'
",
      "cwd": "VSCODECONFIG
echo -n "\"$REPO_ROOT\""
cat << 'VSCODECONFIG2'
"
    },
    "rustynet-gate-runner": {
      "command": "VSCODECONFIG2
echo -n "\"$INSTALL_DIR/rustynet-mcp-gate-runner\""
cat << 'VSCODECONFIG3'
",
      "cwd": "VSCODECONFIG3
echo -n "\"$REPO_ROOT\""
cat << 'VSCODECONFIG4'
"
    },
    "rustynet-lab-state": {
      "command": "VSCODECONFIG4
echo -n "\"$INSTALL_DIR/rustynet-mcp-lab-state\""
cat << 'VSCODECONFIG5'
",
      "cwd": "VSCODECONFIG5
echo -n "\"$REPO_ROOT\""
cat << 'ENDOFFILE'
"
    }
  }
}

========================================
 Generic / Other MCP Clients
========================================

Any MCP-compatible client needs:
- Command (absolute path to binary)
- Working directory (the Rustynet repo root)

Server binaries:
  rustynet-mcp-repo-context  — 10 tools for doc precedence, requirements, security
  rustynet-mcp-gate-runner   —  9 tools for quality gates, builds, audits
  rustynet-mcp-lab-state     — 11 tools for VM lab discovery, recovery, diagnostics

All three servers require the working directory to be the Rustynet repo root.
ENDOFFILE
