#!/usr/bin/env python3
"""
Bug Bounty Platform MCP Server

Exposes bug bounty platform APIs as MCP tools for Claude Code.

Setup:
    bash mcp-bounty-server/setup-mcp.sh          # Install deps + test
    python3 mcp-bounty-server/server.py --test    # Quick self-test

Configure via environment variables:
    HACKERONE_USERNAME, HACKERONE_TOKEN
    BUGCROWD_EMAIL, BUGCROWD_PASSWORD, BUGCROWD_TOTP_SECRET
    INTIGRITI_TOKEN              # Personal Access Token (researcher API)
    INTIGRITI_SPA_COOKIE         # Optional: __Host-Intigriti.Web.Researcher
                                 # cookie value from devtools. Enables rich
                                 # policy.md sections (in-scope intro, OOS
                                 # rules, severity, FAQ, bounty table).
                                 # Lasts ~2 weeks; refresh when expired.
    YESWEHACK_TOKEN
"""

import asyncio
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path


def _atomic_write_text(path: Path, content: str) -> None:
    """Write ``content`` to ``path`` atomically via temp + os.replace.

    Used for every scope/policy/hacktivity/brain file so a crash mid-sync
    never leaves a truncated file that downstream scope_check might parse
    as "scope is legitimately empty".
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        f.write(content)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass
    os.replace(tmp, path)

# Ensure the server's own directory is on the import path,
# regardless of what CWD the parent process uses.
SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
if SERVER_DIR not in sys.path:
    sys.path.insert(0, SERVER_DIR)

# --- Import our modules (these don't need mcp) ---
try:
    from models import (
        Platform,
        ProgramPolicy,
        ProgramScope,
        Severity,
        _yaml_quote,
        hacktivity_to_brain,
        scope_to_markdown,
        scope_to_txt,
        scope_to_yaml,
    )
    from providers import build_registry, get_provider, list_platforms
    from submissions import ReportSubmission
    from submit_handlers import SUBMIT_HANDLERS, save_draft
except ImportError as e:
    print(f"FATAL: Failed to import server modules: {e}", file=sys.stderr)
    print(f"  Server directory: {SERVER_DIR}", file=sys.stderr)
    print(f"  sys.path: {sys.path[:3]}", file=sys.stderr)
    sys.exit(1)

# --- Quick self-test mode ---
if "--test" in sys.argv:
    print("=== MCP Bounty Server Self-Test ===")
    print(f"  Server dir: {SERVER_DIR}")
    print(f"  ✅ Internal modules imported OK")

    try:
        from mcp.server import Server
        from mcp.server.stdio import stdio_server
        from mcp.types import TextContent, Tool
        print(f"  ✅ MCP SDK imported OK")
    except ImportError as e:
        print(f"  ❌ MCP SDK missing: {e}")
        print(f"     Fix: pip install mcp")
        sys.exit(1)

    registry = build_registry()
    platforms = list_platforms(registry)
    configured = sum(1 for p in platforms if p["configured"])
    print(f"  ✅ {len(platforms)} platforms registered ({configured} configured)")

    for p in platforms:
        status = "✅" if p["configured"] else "⚠ "
        print(f"     {status} {p['name']} ({p['platform']})")

    print(f"\n  Server is ready. Add to .claude/settings.json:")
    print(f'    "mcpServers": {{')
    print(f'      "bounty-platforms": {{')
    print(f'        "command": "python3",')
    print(f'        "args": ["{SERVER_DIR}/server.py"]')
    print(f'      }}')
    print(f'    }}')
    sys.exit(0)

# --- Import MCP SDK ---
try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool
except ImportError:
    print(
        "FATAL: MCP SDK not installed.\n"
        "  Fix: pip install mcp\n"
        "  Or run: bash mcp-bounty-server/setup-mcp.sh",
        file=sys.stderr,
    )
    sys.exit(1)

server = Server("bounty-platforms")
registry = build_registry()


def _render_scope_placeholder(platform_name: str, platform_id: str, program: str) -> str:
    """Fallback scope markdown when provider scope is unavailable."""
    return "\n".join([
        f"# Scope: {program}",
        "",
        f"- Platform: `{platform_id}` ({platform_name})",
        "- Scope status: unavailable from API",
        "",
        "## In-Scope Assets",
        "- (not returned by platform API; review program page manually)",
        "",
        "## Out-of-Scope Assets",
        "- (not returned by platform API; review program page manually)",
        "",
        "## Notes",
        "- Run `get_program_scope` again after verifying credentials and handle spelling.",
        "- If still empty, populate `.scope.txt` / `scope.yaml` manually from the program scope page.",
        "",
    ])


def _render_scope_yaml_placeholder(platform_id: str, program: str) -> str:
    """Fallback valid scope.yaml for downstream tooling.

    Critically, includes `scope_mode: placeholder` as a machine-readable
    sentinel. `scope_check.py` treats any file with this flag as a hard
    NO_SCOPE_FILE equivalent — empty `in_scope: []` / `out_of_scope: []`
    without the sentinel looks identical to a legitimately-empty scope and
    could otherwise be mis-interpreted downstream as "nothing is out of
    scope" or "program is locked down". Do NOT remove the sentinel without
    also updating `scope_check.load_scope_yaml`.
    """
    quoted_program = _yaml_quote(program)
    return "\n".join([
        "# Auto-generated placeholder: API did not return scope data.",
        "# DO NOT test any target against this file — scope_check refuses it.",
        "# Re-run sync with working credentials, or populate in_scope/out_of_scope",
        "# manually, then remove the scope_mode line below.",
        "scope_mode: placeholder",
        f"program: {quoted_program}",
        f"platform: {platform_id}",
        'url: ""',
        'last_updated: ""',
        "",
        "in_scope: []",
        "out_of_scope: []",
        "",
    ])


def _render_scope_txt_placeholder(platform_name: str, program: str) -> str:
    return "\n".join([
        f"# {program}",
        f"# Platform: {platform_name}",
        "# Scope status: unavailable from API",
        "",
        "# In Scope",
        "# (populate manually)",
        "",
        "# Out of Scope",
        "# (populate manually)",
        "",
    ])


def _render_policy_markdown(
    policy: ProgramPolicy | None,
    provider_name: str,
    provider_id: str,
    program: str,
    scope: ProgramScope | None,
) -> str:
    """Render policy.md with resilient fallbacks for empty API payloads."""
    safe_harbor = "No/Unknown"
    restrictions: list[str] = []
    instructions: list[str] = []
    policy_text = ""
    disclosure_policy = ""

    if policy is not None:
        safe_harbor = "Yes" if policy.safe_harbor else "No/Unknown"
        restrictions = list(policy.testing_restrictions or [])
        instructions = list(policy.special_instructions or [])
        policy_text = (policy.policy_text or "").strip()
        disclosure_policy = (policy.disclosure_policy or "").strip()

    lines = [
        f"# Program Policy: {program}",
        "",
        f"- Platform: {provider_name} (`{provider_id}`)",
        f"- Safe harbor: {safe_harbor}",
    ]
    if scope and scope.program_url:
        lines.append(f"- Program URL: {scope.program_url}")

    lines.extend(["", "## Testing Restrictions"])
    if restrictions:
        for item in restrictions:
            lines.append(f"- {item}")
    else:
        lines.append("- (none returned by API)")

    if instructions:
        lines.extend(["", "## Special Instructions"])
        for item in instructions:
            lines.append(f"- {item}")

    if disclosure_policy:
        lines.extend(["", "## Disclosure Policy", disclosure_policy])

    lines.extend(["", "## Full Policy Text"])
    if policy_text:
        lines.append(policy_text)
    else:
        lines.append(
            "No structured policy text was returned by the platform API. "
            "Review the program page manually before active testing."
        )
        lines.append("")
        lines.append("Suggested follow-up:")
        lines.append("- Verify your platform credentials (if required).")
        lines.append("- Confirm the program handle is correct.")
        lines.append("- Copy policy details from the platform page into this file.")

    lines.append("")
    return "\n".join(lines)


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="list_platforms",
            description="List all supported bug bounty platforms and their configuration status.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="get_program_scope",
            description=(
                "Fetch the in-scope and out-of-scope assets for a bug bounty program. "
                "Returns structured scope data including asset types, eligibility, and bounty ranges. "
                "Use this BEFORE testing any target to populate scope files."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "platform": {
                        "type": "string",
                        "description": "Platform ID: hackerone, bugcrowd, intigriti, immunefi, yeswehack, etc.",
                    },
                    "program": {
                        "type": "string",
                        "description": "Program handle/slug as it appears in the platform URL.",
                    },
                },
                "required": ["platform", "program"],
            },
        ),
        Tool(
            name="get_program_policy",
            description=(
                "Fetch the program policy, testing guidelines, disclosure rules, and special instructions. "
                "Returns safe harbor status, testing restrictions, and the full policy text."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "platform": {"type": "string", "description": "Platform ID"},
                    "program": {"type": "string", "description": "Program handle/slug"},
                },
                "required": ["platform", "program"],
            },
        ),
        Tool(
            name="search_hacktivity",
            description=(
                "Search disclosed reports and hacktivity for a program. "
                "Use this to check for duplicate vulnerabilities before submitting. "
                "Returns report titles, severity, state, bounty amounts, and vulnerability types."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "platform": {"type": "string", "description": "Platform ID"},
                    "program": {"type": "string", "description": "Program handle/slug"},
                    "query": {
                        "type": "string",
                        "description": "Search query to filter reports (e.g., 'XSS', 'IDOR', 'authentication'). Leave empty for all recent.",
                        "default": "",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max number of reports to return.",
                        "default": 30,
                    },
                },
                "required": ["platform", "program"],
            },
        ),
        Tool(
            name="sync_program",
            description=(
                "Fetch scope, policy, and hacktivity from a platform and write them to local files. "
                "Creates .scope.txt, scope.yaml, scope.md, policy.md, and hacktivity.md in the target directory. "
                "Also updates the brain's target knowledge if a brain directory exists. "
                "Run this when starting a new engagement to auto-populate everything."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "platform": {"type": "string", "description": "Platform ID"},
                    "program": {"type": "string", "description": "Program handle/slug"},
                    "target_dir": {
                        "type": "string",
                        "description": "Directory to write files to. Defaults to current directory.",
                        "default": ".",
                    },
                },
                "required": ["platform", "program"],
            },
        ),
        Tool(
            name="draft_report",
            description=(
                "Create a local draft report ready for review before submission. "
                "Formats the report for the target platform (HackerOne, Bugcrowd, etc.) "
                "and saves it as a markdown file. Review the draft before using submit_report."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "platform": {"type": "string", "description": "Target platform ID"},
                    "program": {"type": "string", "description": "Program handle/slug"},
                    "title": {"type": "string", "description": "Report title: [Vuln Type] in [Component] allows [Impact]"},
                    "severity": {"type": "string", "description": "Severity: critical, high, medium, low, informational", "enum": ["critical", "high", "medium", "low", "informational"]},
                    "vulnerability_type": {
                        "type": "string",
                        "description": "Vulnerability type key: XSS, XSS-Stored, XSS-DOM, SQLI, CSRF, SSRF, IDOR, Auth-Bypass, Info-Disclosure, Open-Redirect, RCE, XXE, CORS, Subdomain-Takeover, Business-Logic, Race-Condition, Privilege-Escalation",
                    },
                    "asset": {"type": "string", "description": "The affected in-scope asset (URL or identifier)"},
                    "description": {"type": "string", "description": "Full vulnerability description"},
                    "steps_to_reproduce": {"type": "string", "description": "Numbered reproduction steps"},
                    "impact": {"type": "string", "description": "Impact statement"},
                    "cvss_vector": {"type": "string", "description": "CVSS vector string (use CVSS:3.1/ for HackerOne, CVSS:4.0/ for others)", "default": ""},
                    "remediation": {"type": "string", "description": "Fix recommendation", "default": ""},
                    "poc_files": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Paths to PoC files (HTML, scripts, etc.)",
                        "default": [],
                    },
                    "evidence_files": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Paths to evidence files (screenshots, recordings, etc.)",
                        "default": [],
                    },
                },
                "required": ["platform", "program", "title", "severity", "vulnerability_type", "asset", "description", "steps_to_reproduce", "impact"],
            },
        ),
        Tool(
            name="submit_report",
            description=(
                "Submit a vulnerability report to a bug bounty platform. "
                "IMPORTANT: Always use draft_report first and get user confirmation before submitting. "
                "Supports HackerOne, Bugcrowd, Intigriti, and YesWeHack. "
                "Handles platform-specific formatting, weakness taxonomy, and PoC/evidence file attachments."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "platform": {"type": "string", "description": "Target platform ID"},
                    "program": {"type": "string", "description": "Program handle/slug"},
                    "title": {"type": "string", "description": "Report title"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "informational"]},
                    "vulnerability_type": {"type": "string", "description": "Vulnerability type key"},
                    "asset": {"type": "string", "description": "Affected in-scope asset"},
                    "description": {"type": "string", "description": "Full vulnerability description"},
                    "steps_to_reproduce": {"type": "string", "description": "Numbered reproduction steps"},
                    "impact": {"type": "string", "description": "Impact statement"},
                    "cvss_vector": {"type": "string", "default": ""},
                    "remediation": {"type": "string", "default": ""},
                    "poc_files": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Paths to PoC files to attach",
                        "default": [],
                    },
                    "evidence_files": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Paths to screenshots/recordings to attach",
                        "default": [],
                    },
                },
                "required": ["platform", "program", "title", "severity", "vulnerability_type", "asset", "description", "steps_to_reproduce", "impact"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "list_platforms":
        platforms = list_platforms(registry)
        lines = ["# Supported Bug Bounty Platforms\n"]
        for p in platforms:
            status = "✅ configured" if p["configured"] else "❌ not configured"
            ptype = "API" if p["type"] == "api" else "stub (manual only)"
            lines.append(f"- **{p['name']}** ({p['platform']}): {status} [{ptype}]")
        lines.append("\nConfigure API keys via environment variables (see server.py header).")
        return [TextContent(type="text", text="\n".join(lines))]

    platform_id = arguments.get("platform", "")
    program = arguments.get("program", "")
    provider = get_provider(registry, platform_id)

    if not provider:
        return [TextContent(type="text", text=f"Unknown platform: {platform_id}. Run list_platforms to see available options.")]
    if not provider.is_configured and name != "sync_program":
        return [TextContent(type="text", text=f"{provider.platform_name} is not configured. Set the required environment variables.")]

    try:
        if name == "get_program_scope":
            scope = await provider.get_scope(program)
            if not scope:
                return [TextContent(type="text", text=f"Program '{program}' not found on {provider.platform_name}.")]
            text = scope_to_yaml(scope)
            summary = f"# Scope: {scope.program_name}\n\nIn scope: {len(scope.in_scope)} assets, Out of scope: {len(scope.out_of_scope)} assets\n\n```yaml\n{text}```"
            return [TextContent(type="text", text=summary)]

        elif name == "get_program_policy":
            policy = await provider.get_policy(program)
            if not policy:
                return [TextContent(type="text", text=f"Policy not found for '{program}' on {provider.platform_name}.")]
            lines = [
                f"# Policy: {program} ({provider.platform_name})\n",
                f"Safe harbor: {'Yes' if policy.safe_harbor else 'No/Unknown'}",
            ]
            if policy.testing_restrictions:
                lines.append("\n## Testing Restrictions")
                for r in policy.testing_restrictions:
                    lines.append(f"- {r}")
            if policy.policy_text:
                lines.append(f"\n## Full Policy\n{policy.policy_text}")
            return [TextContent(type="text", text="\n".join(lines))]

        elif name == "search_hacktivity":
            query = arguments.get("query", "")
            limit = arguments.get("limit", 30)
            entries = await provider.search_hacktivity(program, query, limit)
            if not entries:
                return [TextContent(type="text", text=f"No disclosed reports found for '{program}' on {provider.platform_name}.")]
            lines = [f"# Hacktivity: {program} ({len(entries)} reports)\n"]
            for e in entries:
                bounty = f" ${int(e.bounty_amount)}" if e.bounty_amount else ""
                lines.append(f"- [{e.severity.value.upper()}]{bounty} {e.title} ({e.state})")
                if e.asset:
                    lines.append(f"  Asset: {e.asset}")
            return [TextContent(type="text", text="\n".join(lines))]

        elif name == "sync_program":
            target_dir = Path(arguments.get("target_dir", "."))
            target_dir.mkdir(parents=True, exist_ok=True)

            results = []
            if not provider.is_configured:
                results.append(
                    f"⚠  {provider.platform_name} is not configured (API calls will fail). "
                    "Placeholder files will be written; scope_check refuses to use them."
                )

            # Fetch scope
            scope = await provider.get_scope(program)
            if scope:
                _atomic_write_text(target_dir / ".scope.txt", scope_to_txt(scope))
                _atomic_write_text(target_dir / "scope.yaml", scope_to_yaml(scope))
                _atomic_write_text(target_dir / "scope.md", scope_to_markdown(scope))
                results.append(f"✅ Scope written ({len(scope.in_scope)} in-scope, {len(scope.out_of_scope)} out-of-scope)")
            else:
                scope_txt = target_dir / ".scope.txt"
                scope_yaml = target_dir / "scope.yaml"
                scope_md = target_dir / "scope.md"
                # Only preserve if existing scope.yaml is NOT a placeholder —
                # otherwise we'd cache the "platform API is down" state forever.
                existing_is_real = (
                    scope_txt.exists() and scope_yaml.exists() and scope_md.exists()
                    and "scope_mode: placeholder" not in scope_yaml.read_text()
                )
                if existing_is_real:
                    results.append("⚠  Scope not available from API; kept existing .scope.txt, scope.yaml, and scope.md")
                else:
                    _atomic_write_text(scope_txt, _render_scope_txt_placeholder(provider.platform_name, program))
                    _atomic_write_text(scope_yaml, _render_scope_yaml_placeholder(provider.platform_id, program))
                    _atomic_write_text(scope_md, _render_scope_placeholder(provider.platform_name, provider.platform_id, program))
                    results.append(
                        "⚠  Scope not available from API; wrote placeholder files with `scope_mode: placeholder`. "
                        "scope_check will REFUSE targets against this — populate manually or re-run sync."
                    )

            # Fetch policy
            policy = await provider.get_policy(program)
            policy_md = _render_policy_markdown(
                policy=policy,
                provider_name=provider.platform_name,
                provider_id=provider.platform_id,
                program=program,
                scope=scope,
            )
            _atomic_write_text(target_dir / "policy.md", policy_md)
            if policy and (policy.policy_text or policy.testing_restrictions or policy.special_instructions):
                results.append("✅ Policy written")
            else:
                results.append("⚠  Policy API returned limited data; wrote resilient policy.md fallback")

            # Fetch hacktivity
            entries = await provider.search_hacktivity(program, limit=50)
            hacktivity_md = ""
            if entries:
                program_name = scope.program_name if scope else program
                hacktivity_md = hacktivity_to_brain(entries, program_name)
                _atomic_write_text(target_dir / "hacktivity.md", hacktivity_md)
                results.append(f"✅ Hacktivity written ({len(entries)} reports)")
            else:
                results.append("⚠  No hacktivity available")

            # Seed brain target file if brain exists. brain.py's brief/record
            # commands look for `targets/<slug>.md` (slugify in tools/brain.py
            # strips `://`, `/`, `.`, `:`). The previous code wrote
            # `<slug>-hacktivity.md` — a sibling file brief never found — so
            # `/brain brief <program>` reported "No prior knowledge" right
            # after a successful sync. Now we create the canonical target file
            # with the standard brain template and append hacktivity as a
            # section, matching what `brain.py ensure_target_file` produces.
            brain_dir = target_dir / ".claude" / "agent-memory-local" / "brain"
            if brain_dir.exists():
                targets_dir = brain_dir / "targets"
                targets_dir.mkdir(parents=True, exist_ok=True)
                slug = (
                    program.replace("://", "-")
                    .replace("/", "-")
                    .replace(".", "-")
                    .replace(":", "-")
                    .strip("-")
                )
                target_file = targets_dir / f"{slug}.md"
                today = datetime.now().strftime("%Y-%m-%d")
                header = (
                    f"---\ntarget: {slug}\nfirst_seen: {today}\n"
                    f"last_updated: {today}\nstatus: active\n---\n"
                    f"# {scope.program_name if scope else program}\n\n"
                    "## Tech Stack\n(not yet identified)\n\n"
                    "## Tested Vectors\n(none yet)\n\n"
                    "## Open Questions\n(none yet)\n"
                )
                hacktivity_section = (
                    f"\n## Hacktivity Insights (synced {today})\n\n{hacktivity_md}\n"
                    if hacktivity_md
                    else ""
                )

                if target_file.exists():
                    # Preserve existing hunter notes; refresh timestamp and
                    # replace any stale hacktivity block with fresh data.
                    content = target_file.read_text()
                    content = re.sub(
                        r"^last_updated:.*$",
                        f"last_updated: {today}",
                        content,
                        count=1,
                        flags=re.MULTILINE,
                    )
                    content = re.sub(
                        r"\n## Hacktivity Insights.*?(?=\n## |\Z)",
                        "",
                        content,
                        flags=re.DOTALL,
                    ).rstrip() + "\n"
                    if hacktivity_section:
                        content += hacktivity_section
                    _atomic_write_text(target_file, content)
                    results.append(f"✅ Brain target refreshed: targets/{slug}.md")
                else:
                    _atomic_write_text(target_file, header + hacktivity_section)
                    results.append(f"✅ Brain target created: targets/{slug}.md")

            return [TextContent(type="text", text=f"# Sync: {program} ({provider.platform_name})\n\n" + "\n".join(results))]

        elif name == "draft_report":
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW, "informational": Severity.INFO}
            report = ReportSubmission(
                title=arguments["title"],
                severity=sev_map.get(arguments["severity"], Severity.MEDIUM),
                description=arguments["description"],
                steps_to_reproduce=arguments["steps_to_reproduce"],
                impact=arguments["impact"],
                vulnerability_type=arguments.get("vulnerability_type", ""),
                asset=arguments.get("asset", ""),
                cvss_vector=arguments.get("cvss_vector", ""),
                remediation=arguments.get("remediation", ""),
                poc_files=list(arguments.get("poc_files") or []),
                evidence_files=list(arguments.get("evidence_files") or []),
            )
            draft_path = save_draft(report, platform_id, program)
            return [TextContent(type="text", text=(
                f"# Draft Report Saved\n\n"
                f"File: `{draft_path}`\n"
                f"Platform: {provider.platform_name}\n"
                f"Program: {program}\n"
                f"Severity: {arguments['severity']}\n\n"
                f"**Review the draft file before submitting.** "
                f"When ready, use `submit_report` with the same parameters."
            ))]

        elif name == "submit_report":
            handler = SUBMIT_HANDLERS.get(platform_id)
            if not handler:
                return [TextContent(type="text", text=(
                    f"Report submission is not yet supported for {provider.platform_name}. "
                    f"Supported platforms: {', '.join(SUBMIT_HANDLERS.keys())}. "
                    f"Use `draft_report` to create a local draft, then submit manually."
                ))]

            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW, "informational": Severity.INFO}
            report = ReportSubmission(
                title=arguments["title"],
                severity=sev_map.get(arguments["severity"], Severity.MEDIUM),
                description=arguments["description"],
                steps_to_reproduce=arguments["steps_to_reproduce"],
                impact=arguments["impact"],
                vulnerability_type=arguments.get("vulnerability_type", ""),
                asset=arguments.get("asset", ""),
                cvss_vector=arguments.get("cvss_vector", ""),
                remediation=arguments.get("remediation", ""),
                poc_files=list(arguments.get("poc_files") or []),
                evidence_files=list(arguments.get("evidence_files") or []),
            )

            # Build platform-specific kwargs
            import os as _os
            kwargs = {"report": report, "program_handle": program}
            if platform_id == "hackerone":
                kwargs["username"] = _os.environ.get("HACKERONE_USERNAME", "")
                kwargs["token"] = _os.environ.get("HACKERONE_TOKEN", "")
            elif platform_id == "bugcrowd":
                kwargs["token"] = _os.environ.get("BUGCROWD_TOKEN", "")
            elif platform_id == "intigriti":
                kwargs["token"] = _os.environ.get("INTIGRITI_TOKEN", "")
            elif platform_id == "yeswehack":
                kwargs["token"] = _os.environ.get("YESWEHACK_TOKEN", "")

            result = handler(**kwargs)

            if result.success:
                text = (
                    f"# ✅ Report Submitted\n\n"
                    f"Platform: {provider.platform_name}\n"
                    f"Report ID: {result.report_id}\n"
                    f"URL: {result.report_url or 'N/A'}\n"
                    f"Status: {result.status}\n\n"
                    f"{result.message}"
                )
            elif result.status == "draft_saved":
                text = (
                    f"# 📝 Draft Saved (Manual Submission Required)\n\n"
                    f"Platform: {provider.platform_name}\n\n"
                    f"{result.message}"
                )
            else:
                text = (
                    f"# ❌ Submission Failed\n\n"
                    f"Platform: {provider.platform_name}\n"
                    f"Error: {result.message}\n\n"
                    f"The report was NOT submitted. Check credentials and try again, "
                    f"or use `draft_report` to save locally and submit manually."
                )
            return [TextContent(type="text", text=text)]

    except PermissionError as e:
        return [TextContent(type="text", text=f"Authentication error: {e}")]
    except (KeyError, ValueError, TypeError) as e:
        # Shape errors in the API response or tool arguments — not a bug in the
        # server, but caller needs to know with the specific class so they can
        # distinguish "wrong argument" from "bad upstream data".
        return [TextContent(type="text", text=f"Input/schema error ({type(e).__name__}): {e}")]
    except (OSError, IOError) as e:
        # Filesystem write failure during sync — critical, the workspace may
        # be left in a partial-sync state. Surface the specific errno so the
        # operator can diagnose (disk full, permissions, etc.).
        return [TextContent(type="text", text=f"Filesystem error during {name}: {e}")]
    except (asyncio.TimeoutError, ConnectionError) as e:
        # Transient network failures against the platform API. The operator
        # should retry — but we must NOT write placeholder scope as if the
        # API had returned "no data"; that's already prevented by the sentinel.
        return [TextContent(type="text", text=f"Network error calling {provider.platform_name}: {e}")]
    except Exception as e:
        # Anything else is a genuine bug — include traceback class so the
        # operator can file an issue. Still return text (MCP requires it) but
        # make it clear this is unexpected, not a handled error path.
        import traceback
        trace = traceback.format_exc()
        print(f"UNEXPECTED ERROR in {name}: {trace}", file=sys.stderr)
        return [TextContent(
            type="text",
            text=f"UNEXPECTED ERROR in {name}: {type(e).__name__}: {e}\n"
                 f"(See server stderr for full traceback. This is a bug — please report.)",
        )]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
