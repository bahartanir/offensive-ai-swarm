# Security Policy

## Reporting a Vulnerability

If you find a security issue in the pentest-ai-agents project, please report it privately. Do not open a public issue, do not post on social media, do not include the issue in a pull request title.

**Preferred channel:** open a GitHub Security Advisory at
[github.com/0xSteph/pentest-ai-agents/security/advisories/new](https://github.com/0xSteph/pentest-ai-agents/security/advisories/new).

**Backup:** email `security@pentestai.xyz` with the subject `[SECURITY] short description`.

## What to include

- Affected agent file or script (path or filename)
- Affected version (see `VERSION` and `CHANGELOG.md`)
- Reproduction steps
- Impact you observed or believe likely
- Any suggested fix

## What we commit to

- Acknowledge receipt within 3 business days
- Initial triage within 7 business days
- Coordinated disclosure window of up to 90 days for confirmed vulnerabilities
- Credit in the changelog if you want it

## Scope

In scope:

- Agent definition files in `.claude/agents/`
- Slash commands in `.claude/commands/`
- Bash helpers in `db/` (findings.sh, doctor.sh, etc.)
- The installer (`install.sh`)

Out of scope:

- Cloudflare Pages or Cloudflare Workers infrastructure
- Third-party tools the agents drive (nmap, nuclei, ffuf, etc.) — report upstream
- Theoretical issues without reproduction

## Defensive notes

The agents in this repo are designed for authorized penetration testing. They include scope-enforcement primitives, dual-perspective output (offense paired with detection), and refuse to perform mass-target or destructive operations. If you find a way to bypass the scope guard or coerce an agent into out-of-scope behavior, treat that as a security finding worth reporting.
