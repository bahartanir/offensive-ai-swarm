#!/usr/bin/env bash
# pentest-ai session handoff report generator
# Produces a Markdown summary of engagement state for cross-session continuity

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

ensure_db
ENG=$(require_engagement)

section() { echo ""; echo "## $1"; echo ""; }
row() { echo "$1"; }

echo "# Engagement Handoff: $ENG"
echo "Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"

# Engagement info
info=$(db_exec "SELECT client, type, scope, status, start_date FROM engagements WHERE id='$ENG';")
IFS=$'\t' read -r client type scope status start_date <<< "$info"
section "Engagement Summary"
echo "| Field | Value |"
echo "|-------|-------|"
echo "| Client | ${client:-N/A} |"
echo "| Type | ${type:-N/A} |"
echo "| Status | ${status:-N/A} |"
echo "| Scope | ${scope:-N/A} |"
echo "| Started | ${start_date:-N/A} |"

# Hosts
host_count=$(db_exec "SELECT COUNT(*) FROM hosts WHERE engagement_id='$ENG';")
section "Hosts ($host_count)"
if [[ "$host_count" -gt 0 ]]; then
    echo "| IP | Hostname | OS | Role | Status |"
    echo "|----|----------|------|------|--------|"
    db_exec "SELECT ip, hostname, os, role, status FROM hosts WHERE engagement_id='$ENG' ORDER BY ip;" | while IFS=$'\t' read -r ip hn os role st; do
        echo "| ${ip:-} | ${hn:-} | ${os:-} | ${role:-} | ${st:-} |"
    done
fi

# Services
svc_count=$(db_exec "SELECT COUNT(*) FROM services s JOIN hosts h ON s.host_id=h.id WHERE h.engagement_id='$ENG';")
section "Services ($svc_count)"
if [[ "$svc_count" -gt 0 ]]; then
    echo "| Host | Port | Protocol | Service | Version |"
    echo "|------|------|----------|---------|---------|"
    db_exec "SELECT h.ip, s.port, s.protocol, s.service, s.version FROM services s JOIN hosts h ON s.host_id=h.id WHERE h.engagement_id='$ENG' ORDER BY h.ip, s.port;" | while IFS=$'\t' read -r ip port proto svc ver; do
        echo "| ${ip:-} | ${port:-} | ${proto:-} | ${svc:-} | ${ver:-} |"
    done
fi

# Vulns by severity
vuln_count=$(db_exec "SELECT COUNT(*) FROM vulns WHERE engagement_id='$ENG';")
section "Vulnerabilities ($vuln_count)"
for sev in critical high medium low info; do
    count=$(db_exec "SELECT COUNT(*) FROM vulns WHERE engagement_id='$ENG' AND severity='$sev';")
    if [[ "$count" -gt 0 ]]; then
        echo "### ${sev^} ($count)"
        echo ""
        echo "| ID | Title | CVE | Host | Status | Found By |"
        echo "|----|-------|-----|------|--------|----------|"
        db_exec "SELECT v.id, v.title, COALESCE(NULLIF(v.cve,''),'N/A'), COALESCE(h.ip,'N/A'), v.status, COALESCE(v.found_by,'N/A') FROM vulns v LEFT JOIN hosts h ON v.host_id=h.id WHERE v.engagement_id='$ENG' AND v.severity='$sev' ORDER BY v.id;" | while IFS=$'\t' read -r vid title cve hip vst fb; do
            echo "| ${vid:-} | ${title:-} | ${cve:-} | ${hip:-} | ${vst:-} | ${fb:-} |"
        done
        echo ""
    fi
done

# Credentials
cred_count=$(db_exec "SELECT COUNT(*) FROM credentials WHERE engagement_id='$ENG';")
section "Credentials ($cred_count)"
if [[ "$cred_count" -gt 0 ]]; then
    echo "| Username | Domain | Type | Access | Source | Host |"
    echo "|----------|--------|------|--------|--------|------|"
    db_exec "SELECT c.username, c.domain, c.secret_type, c.access_level, c.source, h.ip FROM credentials c LEFT JOIN hosts h ON c.host_id=h.id WHERE c.engagement_id='$ENG' ORDER BY c.id;" | while IFS=$'\t' read -r user dom stype acc src hip; do
        echo "| ${user:-} | ${dom:-} | ${stype:-} | ${acc:-} | ${src:-} | ${hip:-} |"
    done
fi

# Attack chains
chain_count=$(db_exec "SELECT COUNT(*) FROM chains WHERE engagement_id='$ENG';")
section "Attack Chains ($chain_count)"
if [[ "$chain_count" -gt 0 ]]; then
    db_exec "SELECT id, name, score, status, steps, mitre_ids FROM chains WHERE engagement_id='$ENG' ORDER BY score DESC;" | while IFS=$'\t' read -r cid cname cscore cstatus csteps cmitre; do
        echo "### ${cname:-Unnamed} (Score: ${cscore:-N/A}, Status: ${cstatus:-unknown})"
        echo ""
        if [[ -n "${cmitre:-}" ]]; then echo "MITRE: $cmitre"; echo ""; fi
        if [[ -n "${csteps:-}" ]]; then echo "Steps: $csteps"; echo ""; fi
    done
fi

# Session log (last 30)
log_count=$(db_exec "SELECT COUNT(*) FROM session_log WHERE engagement_id='$ENG';")
section "Recent Activity (last 30 of $log_count)"
if [[ "$log_count" -gt 0 ]]; then
    echo "| Timestamp | Agent | Action | Summary |"
    echo "|-----------|-------|--------|---------|"
    db_exec "SELECT created_at, agent, action, summary FROM session_log WHERE engagement_id='$ENG' ORDER BY id DESC LIMIT 30;" | while IFS=$'\t' read -r ts ag ac sm; do
        echo "| ${ts:-} | ${ag:-} | ${ac:-} | ${sm:-} |"
    done
fi

# Next steps (auto-generated suggestions)
section "Suggested Next Steps"
unconfirmed=$(db_exec "SELECT COUNT(*) FROM vulns WHERE engagement_id='$ENG' AND status='unconfirmed';")
untested_creds=$(db_exec "SELECT COUNT(*) FROM credentials WHERE engagement_id='$ENG' AND valid=2;")
incomplete_chains=$(db_exec "SELECT COUNT(*) FROM chains WHERE engagement_id='$ENG' AND status IN ('identified','in_progress');")

if [[ "$unconfirmed" -gt 0 ]]; then
    echo "- [ ] Validate $unconfirmed unconfirmed vulnerabilities (use poc-validator)"
fi
if [[ "$untested_creds" -gt 0 ]]; then
    echo "- [ ] Test $untested_creds untested credentials (use credential-tester)"
fi
if [[ "$incomplete_chains" -gt 0 ]]; then
    echo "- [ ] Complete $incomplete_chains attack chains (use exploit-chainer)"
fi
if [[ "$unconfirmed" -eq 0 && "$untested_creds" -eq 0 && "$incomplete_chains" -eq 0 ]]; then
    echo "- All findings validated. Ready for report generation."
fi
