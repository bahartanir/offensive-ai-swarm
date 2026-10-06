#!/usr/bin/env python3
"""
brain.py — Persistent engagement knowledge base manager.

Initializes, queries, and maintains the Brain's knowledge base
for the pentest agent suite.

Usage:
    python3 tools/brain.py init                          # Initialize brain structure
    python3 tools/brain.py brief <target>                # Get pre-flight brief
    python3 tools/brain.py record <target> <status> <technique> <details>  # Record result
    python3 tools/brain.py exhausted <target>             # List exhausted techniques
    python3 tools/brain.py status                         # Show engagement status
    python3 tools/brain.py log <message>                  # Append to today's session log
    python3 tools/brain.py capability <target> <capability> [--source <src>] [--confidence N] [--details <txt>] [--from-capability <cap>]
    python3 tools/brain.py capabilities [target]          # Inspect capability graph
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Absolute import so tools/ can be run from any CWD (tests exercise this path).
_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from file_safety import atomic_write_text, load_json_or_quarantine, locked_file  # noqa: E402


def get_brain_dir() -> Path:
    """Find or create the brain's memory directory."""
    # Check for Claude Code agent memory directory
    candidates = [
        Path(".claude/agent-memory-local/brain"),
        Path(".claude/agent-memory/brain"),
        Path("brain-memory"),  # Fallback for non-Claude-Code usage
    ]
    for d in candidates:
        if d.exists():
            return d
    # Default to first candidate
    return candidates[0]


def slugify(target: str) -> str:
    """Convert a target name to a filename-safe slug."""
    return target.replace("://", "-").replace("/", "-").replace(".", "-").replace(":", "-").strip("-")


def today() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def init_brain(brain_dir: Path):
    """Initialize the brain directory structure."""
    dirs = [
        brain_dir / "targets",
        brain_dir / "techniques",
        brain_dir / "patterns",
        brain_dir / "sessions",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)

    # Create MEMORY.md if it doesn't exist
    memory_md = brain_dir / "MEMORY.md"
    if not memory_md.exists():
        memory_md.write_text(f"""# Engagement Brain — Master Index
Created: {today()}

## Active Targets
(none yet)

## Key Findings
(none yet)

## Exhausted Areas
(none yet)

## Active Investigation
(none yet)

## Recent Sessions
- {today()}: Brain initialized
""")

    # Create technique tracking files
    for fname, title in [
        ("exhausted.md", "Exhausted Techniques"),
        ("effective.md", "Effective Techniques"),
        ("waf-bypasses.md", "WAF Behavior & Bypasses"),
    ]:
        fpath = brain_dir / "techniques" / fname
        if not fpath.exists():
            fpath.write_text(f"# {title}\n\n")

    # Create pattern files
    for fname, title in [
        ("tech-stack-vulns.md", "Tech Stack → Vulnerability Patterns"),
        ("false-positives.md", "Known False Positive Patterns"),
    ]:
        fpath = brain_dir / "patterns" / fname
        if not fpath.exists():
            fpath.write_text(f"# {title}\n\n")

    # Create today's session log
    log = brain_dir / "sessions" / f"{today()}.md"
    if not log.exists():
        log.write_text(f"# Session Log — {today()}\n\n- {timestamp()} Brain initialized\n")

    print(f"✅ Brain initialized at {brain_dir}")
    print(f"   Structure:")
    for d in sorted(brain_dir.rglob("*")):
        rel = d.relative_to(brain_dir)
        indent = "  " * len(rel.parts)
        if d.is_dir():
            print(f"   {indent}📁 {d.name}/")
        else:
            print(f"   {indent}📄 {d.name}")


def get_target_file(brain_dir: Path, target: str) -> Path:
    return brain_dir / "targets" / f"{slugify(target)}.md"


def ensure_target_file(brain_dir: Path, target: str) -> Path:
    """Create target file if it doesn't exist."""
    fpath = get_target_file(brain_dir, target)
    fpath.parent.mkdir(parents=True, exist_ok=True)
    if not fpath.exists():
        fpath.write_text(f"""---
target: {target}
first_seen: {today()}
last_updated: {today()}
status: active
---
# {target}

## Tech Stack
(not yet identified)

## Tested Vectors
(none yet)

## Open Questions
(none yet)
""")
    return fpath


def brief_target(brain_dir: Path, target: str):
    """Generate a pre-flight briefing for a target."""
    target_file = get_target_file(brain_dir, target)
    exhausted_file = brain_dir / "techniques" / "exhausted.md"
    effective_file = brain_dir / "techniques" / "effective.md"
    waf_file = brain_dir / "techniques" / "waf-bypasses.md"

    print(f"\n🧠 Brain Briefing: {target}")
    print("=" * 60)

    # Target knowledge
    if target_file.exists():
        content = target_file.read_text()
        print(f"\n📋 Target File: {target_file}")
        print(content)
    else:
        print(f"\n⚠  No prior knowledge of {target}")
        print("   This is a fresh target — no constraints on testing approach.")

    # Exhausted techniques for this target
    if exhausted_file.exists():
        lines = exhausted_file.read_text().splitlines()
        relevant = [l for l in lines if target in l.lower() or slugify(target).replace("-", ".") in l.lower()]
        if relevant:
            print(f"\n🚫 EXHAUSTED — Do NOT retry:")
            for line in relevant:
                print(f"   {line}")
        else:
            print(f"\n✅ No exhausted techniques for this target")

    # Effective techniques
    if effective_file.exists():
        lines = effective_file.read_text().splitlines()
        relevant = [l for l in lines if target in l.lower() or slugify(target).replace("-", ".") in l.lower()]
        if relevant:
            print(f"\n🎯 WORKING — Active vectors:")
            for line in relevant:
                print(f"   {line}")

    # WAF info
    if waf_file.exists():
        content = waf_file.read_text()
        if target in content.lower() or slugify(target).replace("-", ".") in content.lower():
            print(f"\n🛡️ WAF Behavior:")
            for line in content.splitlines():
                if target in line.lower() or slugify(target).replace("-", ".") in line.lower():
                    print(f"   {line}")

    print("\n" + "=" * 60)


# Status vocabulary must match what autopilot, hunt, /chain, and validator
# agents emit. Agents writing `python3 tools/brain.py record ... recon ...`
# used to fail with "ERROR: status must be one of:" because the old
# allow-list only accepted 4 of the 12 statuses those agents produce.
_STATUS_TO_TECHNIQUE_FILE = {
    "active": "effective.md",
    "confirmed": "effective.md",
    "exhausted": "exhausted.md",
    "waf-bypass": "waf-bypasses.md",
    "waf-map": "waf-bypasses.md",
}
_STATUS_TAG = {
    "active": "ACTIVE",
    "browser-rejected": "BROWSER REJECTED",
    "chain": "CHAIN",
    "confirmed": "CONFIRMED",
    "da-killed": "DA KILLED",
    "duplicate": "DUPLICATE",
    "exhausted": "EXHAUSTED",
    "policy": "POLICY",
    "potential": "POTENTIAL",
    "recon": "RECON",
    "waf-bypass": "WAF-BYPASS",
    "waf-map": "WAF-MAP",
}
_STATUS_ICON = {
    "active": "🔄",
    "browser-rejected": "🧯",
    "chain": "🔗",
    "confirmed": "🎯",
    "da-killed": "⚖️",
    "duplicate": "♻️",
    "exhausted": "🚫",
    "policy": "📜",
    "potential": "📝",
    "recon": "🛰️",
    "waf-bypass": "🧪",
    "waf-map": "🛡️",
}
VALID_STATUSES = sorted(_STATUS_TAG)


def _touch_last_updated(target_file: Path) -> None:
    """Refresh `last_updated:` in the target file's YAML frontmatter.

    The previous implementation used a .replace() keyed on the file's
    current last_updated line — this broke on any file where the same
    literal appeared elsewhere (e.g., inside recorded notes), and silently
    did nothing when the date line was absent. `re.sub(count=1)` targets
    only the first occurrence, which is the frontmatter line.
    """
    content = target_file.read_text()
    new_content, n = re.subn(
        r"^last_updated:.*$",
        f"last_updated: {today()}",
        content,
        count=1,
        flags=re.MULTILINE,
    )
    if n == 0:
        # Frontmatter missing this line — append it once rather than silently skip.
        new_content = content.rstrip() + f"\nlast_updated: {today()}\n"
    target_file.write_text(new_content)


def record_result(brain_dir: Path, target: str, status: str, technique: str, details: str):
    """Record a technique result."""
    status = status.lower()
    if status not in _STATUS_TAG:
        print(
            f"ERROR: status must be one of: {', '.join(VALID_STATUSES)}",
            file=sys.stderr,
        )
        sys.exit(1)

    entry = f"[{today()}] {target} | {technique} | {details}"
    target_file = ensure_target_file(brain_dir, target)

    if status == "potential":
        # Rich block in the target file — hunters read this back verbatim.
        with open(target_file, "a") as f:
            f.write(f"\n### {technique}\n- Status: POTENTIAL\n- {details}\n")
    else:
        technique_filename = _STATUS_TO_TECHNIQUE_FILE.get(status)
        if technique_filename:
            with open(brain_dir / "techniques" / technique_filename, "a") as f:
                f.write(entry + "\n")
        with open(target_file, "a") as f:
            f.write(f"\n- [{_STATUS_TAG[status]}] {technique} — {details}\n")

    _touch_last_updated(target_file)
    print(f"{_STATUS_ICON[status]} Recorded {status}: {target} | {technique}")
    append_session_log(brain_dir, f"Recorded {status}: {target} | {technique}")


def list_exhausted(brain_dir: Path, target: str = None):
    """List exhausted techniques."""
    fpath = brain_dir / "techniques" / "exhausted.md"
    if not fpath.exists():
        print("No exhausted techniques recorded yet.")
        return

    lines = fpath.read_text().splitlines()
    entries = [l for l in lines if l.startswith("[")]

    if target:
        entries = [l for l in entries if target.lower() in l.lower()]

    if not entries:
        print(f"No exhausted techniques{f' for {target}' if target else ''}.")
        return

    print(f"🚫 Exhausted Techniques{f' for {target}' if target else ''}:")
    for entry in entries:
        print(f"   {entry}")


def show_status(brain_dir: Path):
    """Show overall engagement status."""
    print("\n🧠 Engagement Brain Status")
    print("=" * 60)

    # Count targets
    targets_dir = brain_dir / "targets"
    if targets_dir.exists():
        targets = list(targets_dir.glob("*.md"))
        print(f"\n📎 Targets: {len(targets)}")
        for t in targets:
            name = t.stem.replace("-", ".")
            print(f"   - {name}")

    # Count exhausted
    exhausted = brain_dir / "techniques" / "exhausted.md"
    if exhausted.exists():
        count = sum(1 for l in exhausted.read_text().splitlines() if l.startswith("["))
        print(f"\n🚫 Exhausted techniques: {count}")

    # Count effective
    effective = brain_dir / "techniques" / "effective.md"
    if effective.exists():
        count = sum(1 for l in effective.read_text().splitlines() if l.startswith("["))
        print(f"\n🎯 Confirmed findings: {count}")

    # Memory index
    memory_md = brain_dir / "MEMORY.md"
    if memory_md.exists():
        lines = len(memory_md.read_text().splitlines())
        print(f"\n📋 MEMORY.md: {lines} lines")

    # Session logs
    sessions = brain_dir / "sessions"
    if sessions.exists():
        logs = list(sessions.glob("*.md"))
        print(f"\n📓 Session logs: {len(logs)}")

    print("\n" + "=" * 60)


def append_session_log(brain_dir: Path, message: str):
    """Append to today's session log."""
    log_dir = brain_dir / "sessions"
    log_dir.mkdir(parents=True, exist_ok=True)
    log = log_dir / f"{today()}.md"
    if not log.exists():
        log.write_text(f"# Session Log — {today()}\n\n")
    with open(log, "a") as f:
        f.write(f"- {timestamp()} {message}\n")


def _capability_graph_path(brain_dir: Path) -> Path:
    return brain_dir / "patterns" / "capability-graph.json"


def _empty_capability_graph() -> dict:
    return {"version": 1, "nodes": {}, "edges": []}


def _clamp_confidence(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def load_capability_graph(brain_dir: Path) -> dict:
    """Load persisted capability graph (or create empty structure).

    A corrupt file is preserved at ``<path>.corrupt-<epoch>`` and a warning is
    emitted; it is NEVER silently overwritten (that would wipe every
    previously-recorded attacker capability).
    """
    path = _capability_graph_path(brain_dir)
    return load_json_or_quarantine(path, _empty_capability_graph)


def save_capability_graph(brain_dir: Path, graph: dict) -> None:
    """Persist the capability graph atomically (temp + os.replace)."""
    path = _capability_graph_path(brain_dir)
    atomic_write_text(path, json.dumps(graph, indent=2))


def record_capability(
    brain_dir: Path,
    target: str,
    capability: str,
    source: str = "",
    confidence: float = 0.7,
    details: str = "",
    from_capability: str = "",
):
    """Persist an attacker capability in the brain capability graph.

    Parallel autopilot subagents may call this concurrently; the
    read-modify-write is serialised via ``locked_file`` on a sidecar ``.lock``
    so simultaneous writers don't lose updates. The write itself is atomic.
    """
    cap_key = capability.strip().lower()
    if not cap_key:
        print("ERROR: capability must be non-empty", file=sys.stderr)
        sys.exit(1)

    confidence_clamped = _clamp_confidence(confidence)
    now = timestamp()
    from_key = from_capability.strip().lower() if from_capability.strip() else ""
    if from_key == cap_key:
        print(
            "WARNING: capability edge from itself to itself is ignored "
            f"({capability}); skipping the self-loop.",
            file=sys.stderr,
        )
        from_key = ""

    path = _capability_graph_path(brain_dir)
    with locked_file(path):
        graph = load_capability_graph(brain_dir)

        node = graph["nodes"].get(cap_key, {"label": capability.strip(), "observations": []})
        node["label"] = capability.strip()
        node["last_seen"] = now
        obs = {
            "target": target,
            "source": source,
            "confidence": confidence_clamped,
            "details": details,
            "seen_at": now,
        }
        node["observations"].append(obs)
        graph["nodes"][cap_key] = node

        if from_key:
            if from_key not in graph["nodes"]:
                graph["nodes"][from_key] = {
                    "label": from_capability.strip(),
                    "observations": [],
                    "last_seen": now,
                }
            edge = {
                "from": from_key,
                "to": cap_key,
                "target": target,
                "source": source,
                "confidence": confidence_clamped,
                "details": details,
                "seen_at": now,
            }
            graph["edges"].append(edge)

        save_capability_graph(brain_dir, graph)
    # Strip newlines from user-controlled fields before logging so they don't
    # corrupt the session log's one-line-per-entry format.
    safe_cap = capability.replace("\n", " ").replace("\r", " ")
    safe_src = (source or "unspecified-source").replace("\n", " ").replace("\r", " ")
    print(f"🧩 Capability recorded: {safe_cap} (target={target}, confidence={confidence_clamped:.2f})")
    append_session_log(brain_dir, f"Capability: {target} | {safe_cap} | {safe_src}")


def list_capabilities(brain_dir: Path, target: str = ""):
    """Print known capabilities (optionally filtered by target)."""
    graph = load_capability_graph(brain_dir)
    if not graph["nodes"]:
        print("No capabilities recorded yet.")
        return
    print("🧩 Capability Graph")
    print("=" * 60)
    for key, node in sorted(graph["nodes"].items()):
        observations = node.get("observations", [])
        if target:
            observations = [o for o in observations if o.get("target", "").lower() == target.lower()]
        if not observations:
            continue
        max_conf = max(float(o.get("confidence", 0)) for o in observations)
        print(f"- {node.get('label', key)}  (observations={len(observations)}, max_confidence={max_conf:.2f})")
        latest = observations[-1]
        print(
            f"  latest: target={latest.get('target','?')} source={latest.get('source','?')} "
            f"seen_at={latest.get('seen_at','?')}"
        )
    if target:
        print(f"\nFiltered by target: {target}")
    print("=" * 60)


def record_endpoint(brain_dir: Path, target: str, endpoint: str, status: str, vuln_class: str = "", details: str = ""):
    """Track individual endpoint test status (I1)."""
    target_file = ensure_target_file(brain_dir, target)
    content = target_file.read_text()
    entry = f"[{timestamp()}] [{status.upper()}] {endpoint} ({vuln_class}) — {details}"
    if "## Tested Endpoints" not in content:
        content += "\n## Tested Endpoints\n"
    content += f"\n{entry}"
    target_file.write_text(content)
    print(f"📍 Endpoint recorded: {endpoint} → {status}")


def list_endpoints(brain_dir: Path, target: str, status_filter: str = ""):
    """List tested/untested endpoints for a target (I1)."""
    target_file = get_target_file(brain_dir, target)
    if not target_file.exists():
        print(f"No data for {target}")
        return
    content = target_file.read_text()
    in_section = False
    tested = []
    for line in content.splitlines():
        if line.strip() == "## Tested Endpoints":
            in_section = True
            continue
        if in_section and line.startswith("## "):
            break
        if in_section and line.strip().startswith("["):
            if not status_filter or status_filter.upper() in line:
                tested.append(line.strip())
    if tested:
        print(f"Tested endpoints for {target} ({len(tested)}):")
        for t in tested:
            print(f"  {t}")
    else:
        print(f"No endpoints recorded for {target}")


def main():
    parser = argparse.ArgumentParser(description="Pentest engagement brain manager")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("init", help="Initialize brain directory structure")
    sub.add_parser("status", help="Show engagement status")

    brief_p = sub.add_parser("brief", help="Get pre-flight briefing for a target")
    brief_p.add_argument("target")

    record_p = sub.add_parser("record", help="Record a technique result")
    record_p.add_argument("target")
    record_p.add_argument("status", choices=VALID_STATUSES)
    record_p.add_argument("technique")
    record_p.add_argument("details")

    exhaust_p = sub.add_parser("exhausted", help="List exhausted techniques")
    exhaust_p.add_argument("target", nargs="?")

    log_p = sub.add_parser("log", help="Append to session log")
    log_p.add_argument("message")

    cap_p = sub.add_parser("capability", help="Record an attacker capability in the graph")
    cap_p.add_argument("target")
    cap_p.add_argument("capability")
    cap_p.add_argument("--source", default="")
    cap_p.add_argument("--confidence", type=float, default=0.7)
    cap_p.add_argument("--details", default="")
    cap_p.add_argument("--from-capability", default="")

    caps_p = sub.add_parser("capabilities", help="List capability graph entries")
    caps_p.add_argument("target", nargs="?")

    # I1: Endpoint tracking
    ep_p = sub.add_parser("endpoint", help="Record an endpoint test result")
    ep_p.add_argument("target")
    ep_p.add_argument("ep_path", help="Endpoint path (e.g. /api/users/123)")
    ep_p.add_argument("ep_status", choices=["tested", "vulnerable", "exhausted", "skipped"])
    ep_p.add_argument("--vuln-class", default="")
    ep_p.add_argument("--details", default="")

    eps_p = sub.add_parser("endpoints", help="List tested endpoints for a target")
    eps_p.add_argument("target")
    eps_p.add_argument("--filter", default="", help="Filter by status")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    brain_dir = get_brain_dir()

    if args.command == "init":
        init_brain(brain_dir)
    elif args.command == "status":
        if not brain_dir.exists():
            print("Brain not initialized. Run: python3 tools/brain.py init")
            sys.exit(1)
        show_status(brain_dir)
    elif args.command == "brief":
        brief_target(brain_dir, args.target)
    elif args.command == "record":
        record_result(brain_dir, args.target, args.status, args.technique, args.details)
    elif args.command == "exhausted":
        list_exhausted(brain_dir, args.target)
    elif args.command == "log":
        append_session_log(brain_dir, args.message)
        print(f"📝 Logged to {brain_dir}/sessions/{today()}.md")
    elif args.command == "capability":
        record_capability(
            brain_dir=brain_dir,
            target=args.target,
            capability=args.capability,
            source=args.source,
            confidence=args.confidence,
            details=args.details,
            from_capability=args.from_capability,
        )
    elif args.command == "capabilities":
        list_capabilities(brain_dir, args.target or "")
    elif args.command == "endpoint":
        record_endpoint(brain_dir, args.target, args.ep_path, args.ep_status, args.vuln_class, args.details)
    elif args.command == "endpoints":
        list_endpoints(brain_dir, args.target, args.filter)


if __name__ == "__main__":
    main()


# --- Circuit breaker (I2) ---

def check_circuit(brain_dir: Path, host: str) -> bool:
    """Check if circuit breaker is tripped for a host. Returns True if safe to proceed."""
    cb_file = brain_dir / "circuit-breaker.json"
    if not cb_file.exists():
        return True
    import json as _json
    data = _json.loads(cb_file.read_text())
    entry = data.get(host, {})
    fails = entry.get("consecutive_fails", 0)
    if fails >= 5:
        backoff_until = entry.get("backoff_until", "")
        if backoff_until and datetime.now().isoformat() < backoff_until:
            print(f"⚡ Circuit OPEN for {host} — {fails} consecutive failures. Backoff until {backoff_until}")
            return False
        # Reset after backoff
        entry["consecutive_fails"] = 0
        data[host] = entry
        cb_file.write_text(_json.dumps(data, indent=2))
    return True


def record_circuit(brain_dir: Path, host: str, success: bool):
    """Record a request result for circuit breaker tracking."""
    import json as _json
    cb_file = brain_dir / "circuit-breaker.json"
    data = _json.loads(cb_file.read_text()) if cb_file.exists() else {}
    entry = data.get(host, {"consecutive_fails": 0, "total_requests": 0})
    entry["total_requests"] = entry.get("total_requests", 0) + 1
    if success:
        entry["consecutive_fails"] = 0
    else:
        entry["consecutive_fails"] = entry.get("consecutive_fails", 0) + 1
        if entry["consecutive_fails"] >= 5:
            # Backoff 60 seconds
            from datetime import timedelta
            entry["backoff_until"] = (datetime.now() + timedelta(seconds=60)).isoformat()
            print(f"⚡ Circuit TRIPPED for {host} — backing off 60s")
    data[host] = entry
    cb_file.write_text(_json.dumps(data, indent=2))
