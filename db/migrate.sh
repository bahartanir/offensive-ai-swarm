#!/usr/bin/env bash
# pentest-ai database migration runner

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

ensure_db

current_version=$(db_exec "SELECT COALESCE(MAX(version), 0) FROM schema_version;" 2>/dev/null || echo "0")
echo "Current schema version: $current_version"

# Apply migrations in order
# Each migration is a function named migrate_vN
# Add new migrations below as the schema evolves

migrate_v1() {
    # v1 is the initial schema, applied by schema.sql
    echo "v1: Initial schema (already applied)"
}

migrate_v2() {
    db_exec "ALTER TABLE vulns ADD COLUMN tool_used TEXT;" 2>/dev/null || true
    db_exec "CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulns(cve);"
    db_exec "CREATE INDEX IF NOT EXISTS idx_vulns_tool_used ON vulns(tool_used);"
    db_exec "INSERT OR IGNORE INTO schema_version (version) VALUES (2);"
    echo "v2: Added tool_used column to vulns; indexed cve and tool_used"
}

LATEST_VERSION=2

if [[ "$current_version" -ge "$LATEST_VERSION" ]]; then
    echo "Database is up to date (v$current_version)."
    exit 0
fi

for ((v=current_version+1; v<=LATEST_VERSION; v++)); do
    echo "Applying migration v$v..."
    "migrate_v$v"
done

echo "Migration complete. Now at v$LATEST_VERSION."
