#!/usr/bin/env python3
"""
statusline.py — Terminal status display for pentest engagements.

Shows: program info, scope stats, agent activity, findings summary,
brain state, cost estimate, and session timeline.

Usage:
    python3 tools/statusline.py              # Full dashboard
    python3 tools/statusline.py --compact    # Single-line for shell prompt
    python3 tools/statusline.py --json       # Machine-readable
    python3 tools/statusline.py --watch      # Auto-refresh every 5s
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path


def read_yaml_field(path: Path, field: str) -> str:
    """Extract a field from a YAML file without pyyaml."""
    if not path.exists():
        return ""
    for line in path.read_text().splitlines():
        if line.startswith(f"{field}:"):
            return line.split(":", 1)[1].strip().strip('"').strip("'")
    return ""


def count_lines_matching(path: Path, pattern: str) -> int:
    if not path.exists():
        return 0
    return sum(1 for l in path.read_text().splitlines() if pattern in l)


def get_program_info() -> dict:
    """Read program info from scope.yaml."""
    scope = Path("scope.yaml")
    return {
        "program": read_yaml_field(scope, "program"),
        "platform": read_yaml_field(scope, "platform"),
        "url": read_yaml_field(scope, "url"),
        "updated": read_yaml_field(scope, "last_updated"),
    }


def get_scope_stats() -> dict:
    """Count in-scope and out-of-scope assets.

    Prefers scope.yaml (structured) over .scope.txt (free-text). For YAML,
    counts `- asset:` entries per top-level section. For free-text, treats
    only bare `# In Scope` / `# Out of Scope` headers as section markers
    (never trailing comments on asset lines).
    """
    yaml_file = Path("scope.yaml")
    if yaml_file.exists():
        in_scope = 0
        out_scope = 0
        section = None
        for line in yaml_file.read_text().splitlines():
            stripped = line.rstrip()
            if stripped == "in_scope:":
                section = "in"
            elif stripped == "out_of_scope:":
                section = "out"
            elif line.lstrip().startswith("- asset:"):
                if section == "in":
                    in_scope += 1
                elif section == "out":
                    out_scope += 1
        return {"in_scope": in_scope, "out_scope": out_scope, "status": "loaded"}

    txt_file = Path(".scope.txt")
    if not txt_file.exists():
        return {"in_scope": 0, "out_scope": 0, "status": "no scope file"}

    in_scope = 0
    out_scope = 0
    section = None
    for line in txt_file.read_text().splitlines():
        stripped = line.strip()
        header = stripped.lstrip("#").strip().lower() if stripped.startswith("#") else None
        if header in ("in scope", "in-scope", "in_scope"):
            section = "in"
            continue
        if header in ("out of scope", "out-of-scope", "out_of_scope", "out scope"):
            section = "out"
            continue
        if stripped and not stripped.startswith("#") and not stripped.startswith("---"):
            if section == "in":
                in_scope += 1
            elif section == "out":
                out_scope += 1
    return {"in_scope": in_scope, "out_scope": out_scope, "status": "loaded"}


def get_brain_stats() -> dict:
    """Read brain knowledge base statistics."""
    brain_dir = Path(".claude/agent-memory-local/brain")
    if not brain_dir.exists():
        return {"initialized": False}

    targets = list((brain_dir / "targets").glob("*.md")) if (brain_dir / "targets").exists() else []

    exhausted = count_lines_matching(brain_dir / "techniques" / "exhausted.md", "[")
    effective = count_lines_matching(brain_dir / "techniques" / "effective.md", "[")

    sessions = list((brain_dir / "sessions").glob("*.md")) if (brain_dir / "sessions").exists() else []

    memory_md = brain_dir / "MEMORY.md"
    memory_lines = len(memory_md.read_text().splitlines()) if memory_md.exists() else 0

    return {
        "initialized": True,
        "targets": len(targets),
        "exhausted": exhausted,
        "effective": effective,
        "sessions": len(sessions),
        "memory_lines": memory_lines,
    }


def get_findings_stats() -> dict:
    """Read findings database statistics."""
    db_path = Path("findings.json")
    if not db_path.exists():
        return {"total": 0, "by_severity": {}}

    try:
        db = json.loads(db_path.read_text())
        findings = db.get("findings", {}).values()
        by_sev = {}
        by_status = {}
        for f in findings:
            sev = f.get("severity", "unknown").lower()
            by_sev[sev] = by_sev.get(sev, 0) + 1
            st = f.get("status", "new")
            by_status[st] = by_status.get(st, 0) + 1
        return {"total": len(db.get("findings", {})), "by_severity": by_sev, "by_status": by_status}
    except:
        return {"total": 0, "by_severity": {}}


def get_evidence_stats() -> dict:
    """Count evidence files."""
    evidence = Path("evidence")
    poc = Path("poc")
    screenshots = list(evidence.glob("**/*.png")) + list(evidence.glob("**/*.jpg")) if evidence.exists() else []
    recordings = list(evidence.glob("**/*.mp4")) + list(evidence.glob("**/*.webm")) if evidence.exists() else []
    pocs = list(poc.glob("**/*")) if poc.exists() else []
    return {"screenshots": len(screenshots), "recordings": len(recordings), "pocs": len(pocs)}


def get_agent_stats() -> dict:
    """Count agent memory files to gauge activity."""
    mem_dir = Path(".claude/agent-memory-local")
    if not mem_dir.exists():
        return {"active_agents": 0, "agents": []}
    agents = []
    for d in sorted(mem_dir.iterdir()):
        if d.is_dir() and d.name != "brain":
            mem = d / "MEMORY.md"
            has_memory = mem.exists() and mem.stat().st_size > 50
            if has_memory:
                agents.append(d.name)
    return {"active_agents": len(agents), "agents": agents}


def get_cost_estimate() -> dict:
    """Estimate cost from session logs."""
    brain_dir = Path(".claude/agent-memory-local/brain")
    sessions_dir = brain_dir / "sessions" if brain_dir.exists() else None
    if not sessions_dir or not sessions_dir.exists():
        return {"sessions": 0, "estimated_cost": "N/A"}

    logs = list(sessions_dir.glob("*.md"))
    total_entries = 0
    for log in logs:
        total_entries += sum(1 for l in log.read_text().splitlines() if l.startswith("- "))

    # Rough estimate: ~$0.05 per agent turn average (orchestrator+inherit subagents)
    est = total_entries * 0.05
    return {"sessions": len(logs), "log_entries": total_entries, "estimated_cost": f"${est:.2f}"}


SEV_ICONS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪", "informational": "⚪"}
SEV_ORDER = ["critical", "high", "medium", "low", "info", "informational"]


def render_full(data: dict):
    """Render full dashboard."""
    prog = data["program"]
    scope = data["scope"]
    brain = data["brain"]
    findings = data["findings"]
    evidence = data["evidence"]
    agents = data["agents"]
    cost = data["cost"]

    w = 60
    print(f"\n{'═' * w}")
    print(f"  🎯 PENTEST ENGAGEMENT DASHBOARD")
    print(f"{'═' * w}")

    # Program
    if prog["program"]:
        print(f"  Program:  {prog['program']}")
        print(f"  Platform: {prog['platform']}")
        if prog["url"]:
            print(f"  URL:      {prog['url']}")
    else:
        print(f"  ⚠  No program configured (run /sync)")

    print(f"{'─' * w}")

    # Scope
    if scope["status"] == "loaded":
        print(f"  📋 Scope: {scope['in_scope']} in-scope, {scope['out_scope']} out-of-scope")
    else:
        print(f"  📋 Scope: not configured")

    # Brain
    if brain["initialized"]:
        print(f"  🧠 Brain: {brain['targets']} targets, {brain['exhausted']} exhausted, {brain['effective']} effective")
        print(f"           {brain['memory_lines']} memory lines, {brain['sessions']} sessions")
    else:
        print(f"  🧠 Brain: not initialized (run /brain init)")

    print(f"{'─' * w}")

    # Findings
    print(f"  🔍 Findings: {findings['total']} total")
    if findings["by_severity"]:
        parts = []
        for sev in SEV_ORDER:
            count = findings["by_severity"].get(sev, 0)
            if count:
                parts.append(f"{SEV_ICONS.get(sev, '⚫')}{count} {sev}")
        if parts:
            print(f"     {' │ '.join(parts)}")
    if findings.get("by_status"):
        status_parts = [f"{k}: {v}" for k, v in sorted(findings["by_status"].items())]
        print(f"     Status: {', '.join(status_parts)}")

    # Evidence
    ev = evidence
    if ev["screenshots"] or ev["recordings"] or ev["pocs"]:
        print(f"  📎 Evidence: {ev['screenshots']} screenshots, {ev['recordings']} recordings, {ev['pocs']} PoCs")

    print(f"{'─' * w}")

    # Agents
    if agents["active_agents"] > 0:
        print(f"  🤖 Active agents ({agents['active_agents']}): {', '.join(agents['agents'])}")
    else:
        print(f"  🤖 No agent memories yet")

    # Cost
    print(f"  💰 Est. cost: {cost['estimated_cost']} ({cost.get('log_entries', 0)} operations)")

    print(f"{'═' * w}")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()


def render_compact(data: dict) -> str:
    """Single-line for shell prompt integration."""
    prog = data["program"]
    brain = data["brain"]
    findings = data["findings"]

    name = prog["program"][:20] if prog["program"] else "no-program"
    f_total = findings["total"]
    f_crit = findings["by_severity"].get("critical", 0)
    f_high = findings["by_severity"].get("high", 0)
    exhausted = brain.get("exhausted", 0) if brain.get("initialized") else 0

    parts = [f"🎯{name}"]
    if f_total:
        parts.append(f"🔍{f_total}")
    if f_crit:
        parts.append(f"🔴{f_crit}")
    if f_high:
        parts.append(f"🟠{f_high}")
    if exhausted:
        parts.append(f"🚫{exhausted}")

    return " ".join(parts)


def collect_data() -> dict:
    return {
        "program": get_program_info(),
        "scope": get_scope_stats(),
        "brain": get_brain_stats(),
        "findings": get_findings_stats(),
        "evidence": get_evidence_stats(),
        "agents": get_agent_stats(),
        "cost": get_cost_estimate(),
        "timestamp": datetime.now().isoformat(),
    }


def main():
    parser = argparse.ArgumentParser(description="Pentest engagement status dashboard")
    parser.add_argument("--compact", action="store_true", help="Single-line output for shell prompt")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--watch", action="store_true", help="Auto-refresh every 5s")
    parser.add_argument("--interval", type=int, default=5, help="Refresh interval for --watch")
    args = parser.parse_args()

    if args.watch:
        try:
            while True:
                os.system("clear" if os.name != "nt" else "cls")
                render_full(collect_data())
                time.sleep(args.interval)
        except KeyboardInterrupt:
            pass
        return

    data = collect_data()

    if args.json:
        print(json.dumps(data, indent=2))
    elif args.compact:
        print(render_compact(data))
    else:
        render_full(data)


if __name__ == "__main__":
    main()
