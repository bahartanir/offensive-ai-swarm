#!/usr/bin/env bash
# setup-mcp.sh — Install dependencies and test the MCP bounty server
#
# Run this once per machine before using the MCP server:
#   bash mcp-bounty-server/setup-mcp.sh
#
# Or from a scaffolded workspace:
#   bash tools/../mcp-bounty-server/setup-mcp.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "=== MCP Bounty Server Setup ==="
echo "   Server dir: $SCRIPT_DIR"
echo ""

# Step 1: Check Python
echo "1. Checking Python..."
if ! command -v python3 &>/dev/null; then
    echo "   ❌ python3 not found. Install Python 3.10+."
    exit 1
fi
PYVER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "   ✅ Python $PYVER"

# Step 2: Check uv (MCP SDK is provisioned per-run via `uv run --with mcp`)
echo ""
echo "2. Checking uv (runtime for MCP servers)..."
if ! command -v uv &>/dev/null; then
    echo "   ❌ uv not found. Install from https://docs.astral.sh/uv/getting-started/installation/"
    echo "      Quick install: curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi
echo "   ✅ uv $(uv --version | awk '{print $2}')"

# Step 3: Verify local imports (mcp SDK is fetched on first `uv run`)
echo ""
echo "3. Verifying local server modules..."
python3 -c "
import sys
sys.path.insert(0, '$SCRIPT_DIR')

errors = []

try:
    from models import Platform
except ImportError as e:
    errors.append(f'models: {e}')

try:
    from providers import build_registry
except ImportError as e:
    errors.append(f'providers: {e}')

try:
    from submissions import ReportSubmission
except ImportError as e:
    errors.append(f'submissions: {e}')

try:
    from submit_handlers import SUBMIT_HANDLERS
except ImportError as e:
    errors.append(f'submit_handlers: {e}')

if errors:
    for e in errors:
        print(f'   ❌ {e}')
    sys.exit(1)
else:
    print('   ✅ All local modules OK (mcp SDK is provisioned by uv at runtime)')
"

# Step 4: Check jq (needed by statusline)
echo ""
echo "4. Checking jq (for statusline)..."
if command -v jq &>/dev/null; then
    echo "   ✅ jq $(jq --version 2>/dev/null || echo 'installed')"
else
    echo "   ⚠  jq not found. Statusline needs it. Install: sudo pacman -S jq"
fi

# Step 4b: Check external hunter tools
echo ""
echo "4b. Checking external hunter tools..."

# graphql-path-enum — used by the graphql-audit agent for indirect-path/IDOR discovery
if command -v graphql-path-enum &>/dev/null; then
    echo "   ✅ graphql-path-enum $(graphql-path-enum --version 2>&1 | awk '{print $2}')"
else
    echo "   ⚠  graphql-path-enum not found (used by graphql-audit agent)."
    if command -v cargo &>/dev/null; then
        echo "      Installing via cargo (requires Rust toolchain)..."
        if cargo install --git https://gitlab.com/dee-see/graphql-path-enum --quiet 2>&1 | tail -5; then
            echo "   ✅ graphql-path-enum installed to \$CARGO_HOME/bin"
        else
            echo "   ❌ cargo install failed. Install manually:"
            echo "      cargo install --git https://gitlab.com/dee-see/graphql-path-enum"
        fi
    else
        echo "      Install Rust (https://rustup.rs) then run:"
        echo "      cargo install --git https://gitlab.com/dee-see/graphql-path-enum"
    fi
fi

# Step 5: Check API credentials
echo ""
echo "5. Checking platform credentials..."
[[ -n "$HACKERONE_USERNAME" ]] && echo "   ✅ HACKERONE_USERNAME set" || echo "   ⚠  HACKERONE_USERNAME not set"
[[ -n "$HACKERONE_TOKEN" ]] && echo "   ✅ HACKERONE_TOKEN set" || echo "   ⚠  HACKERONE_TOKEN not set"
[[ -n "$BUGCROWD_TOKEN" ]] && echo "   ⚠  BUGCROWD_TOKEN not set (optional)" || true
[[ -n "$INTIGRITI_TOKEN" ]] && echo "   ⚠  INTIGRITI_TOKEN not set (optional)" || true

# Step 6: Quick server start test (via uv so mcp SDK is resolved)
echo ""
echo "6. Testing server startup (via uv run --with mcp)..."
timeout 10 uv run --with mcp "$SCRIPT_DIR/server.py" < /dev/null 2>/tmp/mcp-test-stderr.log &
SERVER_PID=$!
sleep 5

if kill -0 $SERVER_PID 2>/dev/null; then
    kill $SERVER_PID 2>/dev/null
    wait $SERVER_PID 2>/dev/null
    echo "   ✅ Server starts without errors"
else
    wait $SERVER_PID 2>/dev/null
    EXIT_CODE=$?
    if [[ $EXIT_CODE -eq 124 ]]; then
        echo "   ✅ Server starts OK (timed out waiting for stdin — expected)"
    else
        echo "   ❌ Server crashed (exit $EXIT_CODE)"
        echo "   stderr:"
        cat /tmp/mcp-test-stderr.log 2>/dev/null | head -10
    fi
fi
rm -f /tmp/mcp-test-stderr.log

# Step 7: Print .mcp.json config
echo ""
echo "=== Setup Complete ==="
echo ""
echo "Add this to your project's .mcp.json (already configured if you used scaffold.py):"
echo ""
echo '  "mcpServers": {'
echo '    "bounty-platforms": {'
echo '      "command": "uv",'
echo "      \"args\": [\"run\", \"--with\", \"mcp\", \"$SCRIPT_DIR/server.py\"],"
echo '      "env": {}'
echo '    }'
echo '  }'
