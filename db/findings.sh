#!/usr/bin/env bash
# pentest-ai findings database CLI
# Zero-token-cost persistent storage for engagement data

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

# ─── init ───────────────────────────────────────────────────────────────
cmd_init() {
    local id="${1:-}"
    shift || true
    if [[ -z "$id" ]]; then
        echo "Usage: findings.sh init <engagement-id> [--client X] [--type X] [--scope X]" >&2
        exit 1
    fi
    local client="" type="" scope="" notes=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --client) client="$2"; shift 2 ;;
            --type) type="$2"; shift 2 ;;
            --scope) scope="$2"; shift 2 ;;
            --notes) notes="$2"; shift 2 ;;
            *) echo "Unknown option: $1" >&2; exit 1 ;;
        esac
    done
    ensure_db
    local eid; eid=$(escape_sql "$id")
    local eclient; eclient=$(escape_sql "$client")
    local etype; etype=$(escape_sql "$type")
    local escope; escope=$(escape_sql "$scope")
    local enotes; enotes=$(escape_sql "$notes")
    db_exec "INSERT OR IGNORE INTO engagements (id, client, type, scope, notes, start_date) VALUES ('$eid', '$eclient', '$etype', '$escope', '$enotes', datetime('now'));"
    echo "Engagement '$id' created. Activate with:"
    echo "  export PENTEST_AI_ENGAGEMENT=\"$id\""
}

# ─── use ────────────────────────────────────────────────────────────────
cmd_use() {
    local id="${1:-}"
    if [[ -z "$id" ]]; then
        echo "Usage: findings.sh use <engagement-id>" >&2; exit 1
    fi
    ensure_db
    local count; count=$(db_exec "SELECT COUNT(*) FROM engagements WHERE id='$(escape_sql "$id")';")
    if [[ "$count" -eq 0 ]]; then
        echo "Error: Engagement '$id' not found." >&2; exit 1
    fi
    echo "export PENTEST_AI_ENGAGEMENT=\"$id\""
}

# ─── add host ───────────────────────────────────────────────────────────
cmd_add_host() {
    local ip="${1:-}"
    shift || true
    if [[ -z "$ip" ]]; then
        echo "Usage: findings.sh add host <ip> [--hostname X] [--os X] [--role X] [--agent X] [--notes X]" >&2
        exit 1
    fi
    local hostname="" os="" role="" agent="" notes=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --hostname) hostname="$2"; shift 2 ;;
            --os) os="$2"; shift 2 ;;
            --role) role="$2"; shift 2 ;;
            --agent) agent="$2"; shift 2 ;;
            --notes) notes="$2"; shift 2 ;;
            *) echo "Unknown option: $1" >&2; exit 1 ;;
        esac
    done
    local eng; eng=$(require_engagement)
    db_exec "INSERT OR REPLACE INTO hosts (engagement_id, ip, hostname, os, role, discovered_by, notes, updated_at)
             VALUES ('$(escape_sql "$eng")', '$(escape_sql "$ip")', '$(escape_sql "$hostname")', '$(escape_sql "$os")', '$(escape_sql "$role")', '$(escape_sql "$agent")', '$(escape_sql "$notes")', datetime('now'));"
    local hid; hid=$(get_host_id "$ip" "$eng")
    echo "Host added: $ip (id=$hid)"
}

# ─── add service ────────────────────────────────────────────────────────
cmd_add_service() {
    local host_ip="${1:-}"
    local port="${2:-}"
    shift 2 || true
    if [[ -z "$host_ip" || -z "$port" ]]; then
        echo "Usage: findings.sh add service <host-ip> <port> [--proto X] [--service X] [--version X] [--banner X]" >&2
        exit 1
    fi
    local proto="tcp" service="" version="" banner=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --proto) proto="$2"; shift 2 ;;
            --service) service="$2"; shift 2 ;;
            --version) version="$2"; shift 2 ;;
            --banner) banner="$2"; shift 2 ;;
            *) echo "Unknown option: $1" >&2; exit 1 ;;
        esac
    done
    local eng; eng=$(require_engagement)
    local hid; hid=$(get_host_id "$host_ip" "$eng")
    if [[ -z "$hid" ]]; then
        echo "Error: Host '$host_ip' not found. Add it first: findings.sh add host $host_ip" >&2; exit 1
    fi
    db_exec "INSERT OR REPLACE INTO services (host_id, port, protocol, service, version, banner)
             VALUES ($hid, $port, '$(escape_sql "$proto")', '$(escape_sql "$service")', '$(escape_sql "$version")', '$(escape_sql "$banner")');"
    echo "Service added: $host_ip:$port/$proto ($service)"
}

# ─── add vuln ───────────────────────────────────────────────────────────
cmd_add_vuln() {
    local title="${1:-}"
    shift || true
    if [[ -z "$title" ]]; then
        echo "Usage: findings.sh add vuln <title> --severity <S> [--host X] [--cve X] [--cvss X] [--mitre X] [--tool X] [--evidence X] [--agent X] [--desc X]" >&2
        exit 1
    fi
    local severity="" host="" cve="" cvss="" mitre="" tool="" evidence="" agent="" desc="" notes=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --severity) severity="$2"; shift 2 ;;
            --host) host="$2"; shift 2 ;;
            --cve) cve="$2"; shift 2 ;;
            --cvss) cvss="$2"; shift 2 ;;
            --mitre) mitre="$2"; shift 2 ;;
            --tool) tool="$2"; shift 2 ;;
            --evidence) evidence="$2"; shift 2 ;;
            --agent) agent="$2"; shift 2 ;;
            --desc) desc="$2"; shift 2 ;;
            --notes) notes="$2"; shift 2 ;;
            *) echo "Unknown option: $1" >&2; exit 1 ;;
        esac
    done
    if [[ -z "$severity" ]]; then
        echo "Error: --severity is required (critical, high, medium, low, info)" >&2; exit 1
    fi
    case "$severity" in
        critical|high|medium|low|info) ;;
        *) echo "Error: Invalid severity '$severity'. Use: critical, high, medium, low, info" >&2; exit 1 ;;
    esac
    local eng; eng=$(require_engagement)
    local hid="NULL"
    if [[ -n "$host" ]]; then
        hid=$(get_host_id "$host" "$eng")
        if [[ -z "$hid" ]]; then
            echo "Warning: Host '$host' not found, adding vuln without host link." >&2
            hid="NULL"
        fi
    fi
    local cvss_val="NULL"
    if [[ -n "$cvss" ]]; then cvss_val="$cvss"; fi
    db_exec "INSERT INTO vulns (engagement_id, host_id, title, severity, cvss, cve, description, evidence_file, mitre_id, tool_used, found_by, notes)
             VALUES ('$(escape_sql "$eng")', $hid, '$(escape_sql "$title")', '$(escape_sql "$severity")', $cvss_val, '$(escape_sql "$cve")', '$(escape_sql "$desc")', '$(escape_sql "$evidence")', '$(escape_sql "$mitre")', '$(escape_sql "$tool")', '$(escape_sql "$agent")', '$(escape_sql "$notes")');"
    local vid; vid=$(db_exec "SELECT MAX(id) FROM vulns WHERE engagement_id='$(escape_sql "$eng")' AND title='$(escape_sql "$title")';")
    echo "Vuln added: [$severity] $title (id=$vid)"
}

# ─── add cred ───────────────────────────────────────────────────────────
cmd_add_cred() {
    local username="${1:-}"
    local secret="${2:-}"
    shift 2 || true
    if [[ -z "$username" || -z "$secret" ]]; then
        echo "Usage: findings.sh add cred <username> <secret> --type <T> [--host X] [--domain X] [--source X] [--access X] [--agent X]" >&2
        exit 1
    fi
    local type="" host="" domain="" source="" access="" agent="" notes=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --type) type="$2"; shift 2 ;;
            --host) host="$2"; shift 2 ;;
            --domain) domain="$2"; shift 2 ;;
            --source) source="$2"; shift 2 ;;
            --access) access="$2"; shift 2 ;;
            --agent) agent="$2"; shift 2 ;;
            --notes) notes="$2"; shift 2 ;;
            *) echo "Unknown option: $1" >&2; exit 1 ;;
        esac
    done
    if [[ -z "$type" ]]; then
        echo "Error: --type is required (cleartext, ntlm, krb5tgs, sha512, key)" >&2; exit 1
    fi
    local eng; eng=$(require_engagement)
    local hid="NULL"
    if [[ -n "$host" ]]; then
        hid=$(get_host_id "$host" "$eng")
        if [[ -z "$hid" ]]; then hid="NULL"; fi
    fi
    db_exec "INSERT OR REPLACE INTO credentials (engagement_id, host_id, username, secret, secret_type, domain, source, access_level, found_by, notes)
             VALUES ('$(escape_sql "$eng")', $hid, '$(escape_sql "$username")', '$(escape_sql "$secret")', '$(escape_sql "$type")', '$(escape_sql "$domain")', '$(escape_sql "$source")', '$(escape_sql "$access")', '$(escape_sql "$agent")', '$(escape_sql "$notes")');"
    echo "Credential added: $username ($type)"
}

# ─── add chain ──────────────────────────────────────────────────────────
cmd_add_chain() {
    local name="${1:-}"
    shift || true
    if [[ -z "$name" ]]; then
        echo "Usage: findings.sh add chain <name> [--score X] [--steps 'JSON'] [--mitre X]" >&2
        exit 1
    fi
    local score="NULL" steps="" mitre="" notes=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --score) score="$2"; shift 2 ;;
            --steps) steps="$2"; shift 2 ;;
            --mitre) mitre="$2"; shift 2 ;;
            --notes) notes="$2"; shift 2 ;;
            *) echo "Unknown option: $1" >&2; exit 1 ;;
        esac
    done
    local eng; eng=$(require_engagement)
    db_exec "INSERT INTO chains (engagement_id, name, score, steps, mitre_ids, notes)
             VALUES ('$(escape_sql "$eng")', '$(escape_sql "$name")', $score, '$(escape_sql "$steps")', '$(escape_sql "$mitre")', '$(escape_sql "$notes")');"
    local cid; cid=$(db_exec "SELECT MAX(id) FROM chains WHERE engagement_id='$(escape_sql "$eng")' AND name='$(escape_sql "$name")';")
    echo "Chain added: $name (id=$cid)"
}

# ─── log ────────────────────────────────────────────────────────────────
cmd_log() {
    local agent="${1:-}"
    local action="${2:-}"
    local summary="${3:-}"
    shift 3 || true
    if [[ -z "$agent" || -z "$action" || -z "$summary" ]]; then
        echo "Usage: findings.sh log <agent> <action> <summary> [--detail X]" >&2; exit 1
    fi
    local detail=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --detail) detail="$2"; shift 2 ;;
            *) echo "Unknown option: $1" >&2; exit 1 ;;
        esac
    done
    local eng; eng=$(require_engagement)
    db_exec "INSERT INTO session_log (engagement_id, agent, action, summary, detail)
             VALUES ('$(escape_sql "$eng")', '$(escape_sql "$agent")', '$(escape_sql "$action")', '$(escape_sql "$summary")', '$(escape_sql "$detail")');"
    echo "Logged: [$agent] $action - $summary"
}

# ─── update ─────────────────────────────────────────────────────────────
cmd_update_vuln() {
    local id="${1:-}"
    shift || true
    if [[ -z "$id" ]]; then
        echo "Usage: findings.sh update vuln <id> [--status X] [--poc-output X] [--confirmed-by X]" >&2; exit 1
    fi
    local sets=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --status) sets+=("status='$(escape_sql "$2")'"); shift 2 ;;
            --poc-output) sets+=("poc_output='$(escape_sql "$2")'"); shift 2 ;;
            --confirmed-by) sets+=("confirmed_by='$(escape_sql "$2")'"); shift 2 ;;
            *) echo "Unknown option: $1" >&2; exit 1 ;;
        esac
    done
    if [[ ${#sets[@]} -eq 0 ]]; then
        echo "Error: No fields to update." >&2; exit 1
    fi
    sets+=("updated_at=datetime('now')")
    local set_clause; set_clause=$(IFS=','; echo "${sets[*]}")
    db_exec "UPDATE vulns SET $set_clause WHERE id=$id;"
    echo "Vuln $id updated."
}

cmd_update_chain() {
    local id="${1:-}"
    shift || true
    if [[ -z "$id" ]]; then
        echo "Usage: findings.sh update chain <id> [--status X] [--score X]" >&2; exit 1
    fi
    local sets=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --status) sets+=("status='$(escape_sql "$2")'"); shift 2 ;;
            --score) sets+=("score=$2"); shift 2 ;;
            *) echo "Unknown option: $1" >&2; exit 1 ;;
        esac
    done
    if [[ ${#sets[@]} -eq 0 ]]; then
        echo "Error: No fields to update." >&2; exit 1
    fi
    sets+=("updated_at=datetime('now')")
    local set_clause; set_clause=$(IFS=','; echo "${sets[*]}")
    db_exec "UPDATE chains SET $set_clause WHERE id=$id;"
    echo "Chain $id updated."
}

cmd_update_host() {
    local id="${1:-}"
    shift || true
    if [[ -z "$id" ]]; then
        echo "Usage: findings.sh update host <id> [--os X] [--role X] [--status X]" >&2; exit 1
    fi
    local sets=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --os) sets+=("os='$(escape_sql "$2")'"); shift 2 ;;
            --role) sets+=("role='$(escape_sql "$2")'"); shift 2 ;;
            --status) sets+=("status='$(escape_sql "$2")'"); shift 2 ;;
            *) echo "Unknown option: $1" >&2; exit 1 ;;
        esac
    done
    if [[ ${#sets[@]} -eq 0 ]]; then
        echo "Error: No fields to update." >&2; exit 1
    fi
    sets+=("updated_at=datetime('now')")
    local set_clause; set_clause=$(IFS=','; echo "${sets[*]}")
    db_exec "UPDATE hosts SET $set_clause WHERE id=$id;"
    echo "Host $id updated."
}

# ─── list ───────────────────────────────────────────────────────────────
cmd_list_hosts() {
    local eng; eng=$(require_engagement)
    local where="engagement_id='$(escape_sql "$eng")'"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --role) where="$where AND role='$(escape_sql "$2")'"; shift 2 ;;
            --status) where="$where AND status='$(escape_sql "$2")'"; shift 2 ;;
            *) shift ;;
        esac
    done
    db_exec_csv "SELECT id, ip, hostname, os, role, status, discovered_by, created_at FROM hosts WHERE $where ORDER BY id;"
}

cmd_list_services() {
    local eng; eng=$(require_engagement)
    local join_where="h.engagement_id='$(escape_sql "$eng")'"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --host) join_where="$join_where AND h.ip='$(escape_sql "$2")'"; shift 2 ;;
            --port) join_where="$join_where AND s.port=$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    db_exec_csv "SELECT s.id, h.ip, s.port, s.protocol, s.service, s.version, s.state FROM services s JOIN hosts h ON s.host_id=h.id WHERE $join_where ORDER BY h.ip, s.port;"
}

cmd_list_vulns() {
    local eng; eng=$(require_engagement)
    local where="v.engagement_id='$(escape_sql "$eng")'"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --severity) where="$where AND v.severity='$(escape_sql "$2")'"; shift 2 ;;
            --status) where="$where AND v.status='$(escape_sql "$2")'"; shift 2 ;;
            --host) where="$where AND h.ip='$(escape_sql "$2")'"; shift 2 ;;
            *) shift ;;
        esac
    done
    db_exec_csv "SELECT v.id, v.title, v.severity, v.status, v.cve, h.ip AS host, v.found_by, v.created_at FROM vulns v LEFT JOIN hosts h ON v.host_id=h.id WHERE $where ORDER BY CASE v.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END;"
}

cmd_list_creds() {
    local eng; eng=$(require_engagement)
    local where="c.engagement_id='$(escape_sql "$eng")'"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --domain) where="$where AND c.domain='$(escape_sql "$2")'"; shift 2 ;;
            --type) where="$where AND c.secret_type='$(escape_sql "$2")'"; shift 2 ;;
            --access) where="$where AND c.access_level='$(escape_sql "$2")'"; shift 2 ;;
            *) shift ;;
        esac
    done
    db_exec_csv "SELECT c.id, c.username, c.secret_type, c.domain, c.access_level, c.source, h.ip AS host, c.found_by FROM credentials c LEFT JOIN hosts h ON c.host_id=h.id WHERE $where ORDER BY c.id;"
}

cmd_list_chains() {
    local eng; eng=$(require_engagement)
    local where="engagement_id='$(escape_sql "$eng")'"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --status) where="$where AND status='$(escape_sql "$2")'"; shift 2 ;;
            *) shift ;;
        esac
    done
    db_exec_csv "SELECT id, name, score, status, mitre_ids, created_at FROM chains WHERE $where ORDER BY score DESC;"
}

cmd_list_log() {
    local eng; eng=$(require_engagement)
    local where="engagement_id='$(escape_sql "$eng")'"
    local limit="50"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --agent) where="$where AND agent='$(escape_sql "$2")'"; shift 2 ;;
            --limit) limit="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    db_exec_csv "SELECT id, agent, action, summary, created_at FROM session_log WHERE $where ORDER BY id DESC LIMIT $limit;"
}

# ─── get ────────────────────────────────────────────────────────────────
cmd_get_vuln() {
    local id="${1:-}"
    if [[ -z "$id" ]]; then echo "Usage: findings.sh get vuln <id>" >&2; exit 1; fi
    db_exec_csv "SELECT v.*, h.ip AS host_ip FROM vulns v LEFT JOIN hosts h ON v.host_id=h.id WHERE v.id=$id;"
}

cmd_get_host() {
    local id_or_ip="${1:-}"
    if [[ -z "$id_or_ip" ]]; then echo "Usage: findings.sh get host <id|ip>" >&2; exit 1; fi
    local eng; eng=$(require_engagement)
    if [[ "$id_or_ip" =~ ^[0-9]+$ ]] && ! [[ "$id_or_ip" =~ \. ]]; then
        db_exec_csv "SELECT * FROM hosts WHERE id=$id_or_ip;"
    else
        db_exec_csv "SELECT * FROM hosts WHERE ip='$(escape_sql "$id_or_ip")' AND engagement_id='$(escape_sql "$eng")';"
    fi
}

cmd_get_chain() {
    local id="${1:-}"
    if [[ -z "$id" ]]; then echo "Usage: findings.sh get chain <id>" >&2; exit 1; fi
    db_exec_csv "SELECT * FROM chains WHERE id=$id;"
}

# ─── stats ──────────────────────────────────────────────────────────────
cmd_stats() {
    local eng; eng=$(require_engagement)
    echo "=== Engagement: $eng ==="
    echo ""
    echo "Hosts:       $(db_exec "SELECT COUNT(*) FROM hosts WHERE engagement_id='$eng';")"
    echo "Services:    $(db_exec "SELECT COUNT(*) FROM services s JOIN hosts h ON s.host_id=h.id WHERE h.engagement_id='$eng';")"
    echo "Vulns:       $(db_exec "SELECT COUNT(*) FROM vulns WHERE engagement_id='$eng';")"
    echo "  Critical:  $(db_exec "SELECT COUNT(*) FROM vulns WHERE engagement_id='$eng' AND severity='critical';")"
    echo "  High:      $(db_exec "SELECT COUNT(*) FROM vulns WHERE engagement_id='$eng' AND severity='high';")"
    echo "  Medium:    $(db_exec "SELECT COUNT(*) FROM vulns WHERE engagement_id='$eng' AND severity='medium';")"
    echo "  Low:       $(db_exec "SELECT COUNT(*) FROM vulns WHERE engagement_id='$eng' AND severity='low';")"
    echo "  Confirmed: $(db_exec "SELECT COUNT(*) FROM vulns WHERE engagement_id='$eng' AND status='confirmed';")"
    echo "  Exploited: $(db_exec "SELECT COUNT(*) FROM vulns WHERE engagement_id='$eng' AND status='exploited';")"
    echo "Credentials: $(db_exec "SELECT COUNT(*) FROM credentials WHERE engagement_id='$eng';")"
    echo "Chains:      $(db_exec "SELECT COUNT(*) FROM chains WHERE engagement_id='$eng';")"
    echo "Log entries: $(db_exec "SELECT COUNT(*) FROM session_log WHERE engagement_id='$eng';")"
}

# ─── engagements ────────────────────────────────────────────────────────
cmd_engagements() {
    ensure_db
    db_exec_csv "SELECT id, client, type, status, start_date, created_at FROM engagements ORDER BY created_at DESC;"
}

# ─── export ─────────────────────────────────────────────────────────────
cmd_export() {
    local eng; eng=$(require_engagement)
    local engagement; engagement=$(db_exec_json "SELECT * FROM engagements WHERE id='$eng';")
    local hosts; hosts=$(db_exec_json "SELECT * FROM hosts WHERE engagement_id='$eng';")
    local services; services=$(db_exec_json "SELECT s.* FROM services s JOIN hosts h ON s.host_id=h.id WHERE h.engagement_id='$eng';")
    local vulns; vulns=$(db_exec_json "SELECT * FROM vulns WHERE engagement_id='$eng';")
    local credentials; credentials=$(db_exec_json "SELECT * FROM credentials WHERE engagement_id='$eng';")
    local chains; chains=$(db_exec_json "SELECT * FROM chains WHERE engagement_id='$eng';")
    local session_log; session_log=$(db_exec_json "SELECT * FROM session_log WHERE engagement_id='$eng';")
    echo "{"
    echo "  \"engagement\": $engagement,"
    echo "  \"hosts\": $hosts,"
    echo "  \"services\": $services,"
    echo "  \"vulns\": $vulns,"
    echo "  \"credentials\": $credentials,"
    echo "  \"chains\": $chains,"
    echo "  \"session_log\": $session_log"
    echo "}"
}

# ─── main router ────────────────────────────────────────────────────────
main() {
    local cmd="${1:-}"
    local sub="${2:-}"

    case "$cmd" in
        init) shift; cmd_init "$@" ;;
        use) shift; cmd_use "$@" ;;
        add)
            shift
            case "$sub" in
                host) shift; cmd_add_host "$@" ;;
                service) shift; cmd_add_service "$@" ;;
                vuln) shift; cmd_add_vuln "$@" ;;
                cred) shift; cmd_add_cred "$@" ;;
                chain) shift; cmd_add_chain "$@" ;;
                *) echo "Usage: findings.sh add <host|service|vuln|cred|chain>" >&2; exit 1 ;;
            esac
            ;;
        update)
            shift
            case "$sub" in
                vuln) shift; cmd_update_vuln "$@" ;;
                chain) shift; cmd_update_chain "$@" ;;
                host) shift; cmd_update_host "$@" ;;
                *) echo "Usage: findings.sh update <vuln|chain|host>" >&2; exit 1 ;;
            esac
            ;;
        list)
            shift
            case "$sub" in
                hosts) shift; cmd_list_hosts "$@" ;;
                services) shift; cmd_list_services "$@" ;;
                vulns) shift; cmd_list_vulns "$@" ;;
                creds) shift; cmd_list_creds "$@" ;;
                chains) shift; cmd_list_chains "$@" ;;
                log) shift; cmd_list_log "$@" ;;
                *) echo "Usage: findings.sh list <hosts|services|vulns|creds|chains|log>" >&2; exit 1 ;;
            esac
            ;;
        get)
            shift
            case "$sub" in
                vuln) shift; cmd_get_vuln "$@" ;;
                host) shift; cmd_get_host "$@" ;;
                chain) shift; cmd_get_chain "$@" ;;
                *) echo "Usage: findings.sh get <vuln|host|chain>" >&2; exit 1 ;;
            esac
            ;;
        stats) cmd_stats ;;
        engagements) cmd_engagements ;;
        export) cmd_export ;;
        log) shift; cmd_log "$@" ;;
        -h|--help|help|"") print_help ;;
        *) echo "Unknown command: $cmd. Run 'findings.sh --help' for usage." >&2; exit 1 ;;
    esac
}

main "$@"
