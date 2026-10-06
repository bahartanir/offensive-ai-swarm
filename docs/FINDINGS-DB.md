# Findings Database

Persistent, zero-token-cost storage for penetration testing engagement data. All findings, credentials, hosts, services, and attack chains are stored in a local SQLite database that survives across Claude Code sessions.

## Why

LLM context windows reset between sessions. Without persistent storage, every new session starts from scratch. The findings database solves this by storing engagement data in SQLite, which agents can read and write without burning tokens on re-ingestion.

Compared to vector-based approaches (like Hindsight), this uses zero LLM tokens for storage and retrieval. Data goes in and out as structured queries, not embeddings.

## Quick Start

```bash
# Install (included with standard install)
./install.sh --global

# Initialize an engagement
findings.sh init acme-2024 --client "ACME Corp" --type internal --scope "10.0.0.0/24"

# Set active engagement
export PENTEST_AI_ENGAGEMENT="acme-2024"

# Add findings as you go
findings.sh add host 10.0.0.1 --hostname "dc01.acme.local" --os "Windows Server 2022" --role "Domain Controller" --agent "recon-advisor"
findings.sh add service 10.0.0.1 445 --service "SMB"
findings.sh add vuln "SMB Signing Disabled" --severity medium --host 10.0.0.1 --agent "vuln-scanner"
findings.sh add cred "svc_sql" "Password123" --type cleartext --domain "acme.local" --source "Kerberoasting" --agent "ad-attacker"
findings.sh add chain "DA via Kerberoasting" --score 95 --steps "Kerberoast -> Crack -> MSSQL -> DA" --mitre "T1558.003,T1059.001"

# Check progress
findings.sh stats

# Generate a handoff report for cross-session continuity
bash ~/.pentest-ai/bin/handoff.sh > handoff.md

# Export as JSON
findings.sh export > engagement.json
```

## Commands

| Command | Description |
|---------|-------------|
| `init <id>` | Create a new engagement |
| `use <id>` | Set active engagement (prints export command) |
| `add host <ip>` | Add a discovered host |
| `add service <ip> <port>` | Add a service to a host |
| `add vuln <title>` | Add a vulnerability |
| `add cred <user> <secret>` | Add a credential |
| `add chain <name>` | Add an attack chain |
| `log <agent> <action> <summary>` | Add a session log entry |
| `update vuln <id>` | Update vulnerability status |
| `update chain <id>` | Update chain status |
| `update host <id>` | Update host details |
| `list hosts` | List all hosts |
| `list services` | List all services |
| `list vulns` | List vulnerabilities (filterable by severity, status, host) |
| `list creds` | List credentials |
| `list chains` | List attack chains |
| `list log` | List session activity log |
| `get vuln <id>` | Get full vulnerability details |
| `get host <id\|ip>` | Get full host details |
| `get chain <id>` | Get full chain details |
| `stats` | Engagement summary with counts |
| `engagements` | List all engagements |
| `export` | Export full engagement as JSON |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PENTEST_AI_DB` | `~/.pentest-ai/findings.db` | Database file path |
| `PENTEST_AI_ENGAGEMENT` | `default` | Active engagement ID |
| `PENTEST_AI_HOME` | `~/.pentest-ai` | Data directory |

## Agent Integration

All Tier 2 agents and key Tier 1 agents check for `findings.sh` availability and use it when present. Each agent records its specific data type:

| Agent | Writes |
|-------|--------|
| recon-advisor | hosts, services |
| vuln-scanner | vulnerabilities |
| poc-validator | vulnerability status updates |
| exploit-chainer | attack chains |
| ad-attacker | credentials, vulnerabilities |
| web-hunter | hosts, vulnerabilities |
| bizlogic-hunter | vulnerabilities |
| credential-tester | credentials |
| engagement-planner | engagement init |
| report-generator | reads all data for reports |
| swarm-orchestrator | coordinates all agents, reads stats |

Agents check availability with `command -v findings.sh &>/dev/null` and skip database writes if not installed. No agent depends on the database to function.

## Cross-Session Workflow

```
Session 1: Recon
  findings.sh init client-pentest --client "Client" --type internal
  [recon-advisor writes hosts and services]
  findings.sh stats  # 15 hosts, 42 services

Session 2: Vulnerability Assessment
  export PENTEST_AI_ENGAGEMENT="client-pentest"
  findings.sh list hosts  # pick up where you left off
  [vuln-scanner writes vulns, poc-validator confirms them]
  findings.sh stats  # 8 vulns, 3 confirmed

Session 3: Exploitation
  export PENTEST_AI_ENGAGEMENT="client-pentest"
  findings.sh list vulns --status confirmed  # see confirmed targets
  [exploit-chainer builds chains, ad-attacker harvests creds]
  bash handoff.sh > handoff.md  # full state for next session

Session 4: Reporting
  export PENTEST_AI_ENGAGEMENT="client-pentest"
  findings.sh export > data.json  # report-generator uses this
```

## Schema

The database uses 7 tables: `engagements`, `hosts`, `services`, `vulns`, `credentials`, `chains`, `session_log`, plus a `schema_version` table for migrations.

Full schema is in `db/schema.sql`.

## Technical Notes

- Uses Python sqlite3 module as a fallback when the sqlite3 CLI is not installed
- All queries use parameterized values via `escape_sql` to prevent injection
- Tab-separated output for easy parsing in shell pipelines
- JSON export works with both sqlite3 CLI and Python fallback
- Schema migrations run via `db/migrate.sh`
- Skip installation with `./install.sh --global --no-db`
