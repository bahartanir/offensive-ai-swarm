#!/usr/bin/env bash
# Shared functions for pentest-ai findings database

set -euo pipefail

DB_DIR="${PENTEST_AI_HOME:-$HOME/.pentest-ai}"
DB_PATH="${PENTEST_AI_DB:-$DB_DIR/findings.db}"
ENGAGEMENT="${PENTEST_AI_ENGAGEMENT:-default}"
SCHEMA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
USE_PYTHON_SQLITE=false

db_path() {
    echo "$DB_PATH"
}

ensure_dir() {
    mkdir -p "$DB_DIR"
}

check_sqlite() {
    if command -v sqlite3 &>/dev/null; then
        USE_PYTHON_SQLITE=false
    elif python3 -c "import sqlite3" &>/dev/null; then
        USE_PYTHON_SQLITE=true
    else
        echo "Error: sqlite3 is required. Install with:" >&2
        echo "  sudo apt install sqlite3  (Debian/Ubuntu)" >&2
        echo "  brew install sqlite       (macOS)" >&2
        exit 1
    fi
}

# Detect sqlite backend at source time
check_sqlite

_py_sqlite() {
    local mode="${1:-tab}"
    local sql="${2:-}"
    python3 -c "
import sqlite3, sys, json
conn = sqlite3.connect('$DB_PATH')
conn.execute('PRAGMA foreign_keys=ON')
cur = conn.cursor()
try:
    cur.execute('''$sql''')
    if cur.description:
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
        if '$mode' == 'json':
            result = []
            for row in rows:
                result.append(dict(zip(cols, [v if v is not None else None for v in row])))
            print(json.dumps(result))
        elif '$mode' == 'header':
            print('\t'.join(cols))
            for row in rows:
                print('\t'.join(str(v) if v is not None else '' for v in row))
        else:
            for row in rows:
                print('\t'.join(str(v) if v is not None else '' for v in row))
    elif '$mode' == 'json':
        print('[]')
    conn.commit()
except Exception as e:
    print(str(e), file=sys.stderr)
    sys.exit(1)
finally:
    conn.close()
"
}

_py_sqlite_script() {
    local script_file="$1"
    python3 -c "
import sqlite3
conn = sqlite3.connect('$DB_PATH')
with open('$script_file', 'r') as f:
    conn.executescript(f.read())
conn.close()
"
}

ensure_db() {
    check_sqlite
    ensure_dir
    if [[ ! -f "$DB_PATH" ]]; then
        if [[ "$USE_PYTHON_SQLITE" == true ]]; then
            _py_sqlite_script "$SCHEMA_DIR/schema.sql"
        else
            sqlite3 "$DB_PATH" < "$SCHEMA_DIR/schema.sql"
        fi
    fi
}

db_exec() {
    if [[ "$USE_PYTHON_SQLITE" == true ]]; then
        _py_sqlite "tab" "$1"
    else
        sqlite3 -separator $'\t' "$DB_PATH" "$@"
    fi
}

db_insert() {
    # Insert and return last_insert_rowid in a single connection
    if [[ "$USE_PYTHON_SQLITE" == true ]]; then
        local sql="$1"
        python3 -c "
import sqlite3, sys
conn = sqlite3.connect('$DB_PATH')
conn.execute('PRAGMA foreign_keys=ON')
cur = conn.cursor()
try:
    cur.execute('''$sql''')
    conn.commit()
    print(cur.lastrowid)
except Exception as e:
    print(str(e), file=sys.stderr)
    sys.exit(1)
finally:
    conn.close()
"
    else
        sqlite3 "$DB_PATH" "$1"
        sqlite3 "$DB_PATH" "SELECT last_insert_rowid();"
    fi
}

db_exec_csv() {
    if [[ "$USE_PYTHON_SQLITE" == true ]]; then
        _py_sqlite "header" "$1"
    else
        sqlite3 -header -separator $'\t' "$DB_PATH" "$@"
    fi
}

db_exec_json() {
    if [[ "$USE_PYTHON_SQLITE" == true ]]; then
        _py_sqlite "json" "$1"
    else
        sqlite3 -json "$DB_PATH" "$@"
    fi
}

require_engagement() {
    ensure_db
    local count
    count=$(db_exec "SELECT COUNT(*) FROM engagements WHERE id='$ENGAGEMENT';")
    if [[ "$count" -eq 0 ]]; then
        if [[ "$ENGAGEMENT" == "default" ]]; then
            db_exec "INSERT OR IGNORE INTO engagements (id, client, type, status) VALUES ('default', 'default', 'general', 'active');"
        else
            echo "Error: Engagement '$ENGAGEMENT' not found. Run: findings.sh init $ENGAGEMENT" >&2
            exit 1
        fi
    fi
    echo "$ENGAGEMENT"
}

get_host_id() {
    local ip="$1"
    local eng="$2"
    db_exec "SELECT id FROM hosts WHERE ip='$ip' AND engagement_id='$eng' LIMIT 1;"
}

get_service_id() {
    local host_id="$1"
    local port="$2"
    local proto="${3:-tcp}"
    db_exec "SELECT id FROM services WHERE host_id=$host_id AND port=$port AND protocol='$proto' LIMIT 1;"
}

escape_sql() {
    local val="$1"
    echo "${val//\'/\'\'}"
}

print_help() {
    local cmd="${1:-}"
    case "$cmd" in
        "")
            cat <<'HELP'
pentest-ai findings database

Usage: findings.sh <command> [options]

Commands:
  init <id>           Create a new engagement
  use <id>            Set active engagement (prints export command)
  add host            Add a discovered host
  add service         Add a service to a host
  add vuln            Add a vulnerability
  add cred            Add a credential
  add chain           Add an attack chain
  log                 Add a session log entry
  update vuln         Update vulnerability status
  update chain        Update chain status
  update host         Update host details
  list hosts          List hosts
  list services       List services
  list vulns          List vulnerabilities
  list creds          List credentials
  list chains         List attack chains
  list log            List session log
  get vuln <id>       Get vulnerability details
  get host <id|ip>    Get host details
  get chain <id>      Get chain details
  stats               Show engagement summary
  engagements         List all engagements
  export              Export engagement as JSON

Environment:
  PENTEST_AI_DB           Database path (default: ~/.pentest-ai/findings.db)
  PENTEST_AI_ENGAGEMENT   Active engagement (default: default)
  PENTEST_AI_HOME         Data directory (default: ~/.pentest-ai)

Run 'findings.sh <command> --help' for command-specific help.
HELP
            ;;
    esac
}
