#!/usr/bin/env python3
"""
global_brain.py — Cross-engagement knowledge base.

Maintains universal pentest knowledge that applies across all programs:
WAF behavior patterns, tech stack → vulnerability mappings, and
cumulative response learning.

Stored at ~/.claude/agent-memory/pentest-global/ (user-scope, persists across projects).

Usage:
    python3 tools/global_brain.py init
    python3 tools/global_brain.py learn <category> <knowledge>
    python3 tools/global_brain.py query <topic>
    python3 tools/global_brain.py sync-from-local   # Import local brain learnings
    python3 tools/global_brain.py sync-to-local     # Export relevant global knowledge
    python3 tools/global_brain.py stats
"""

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path


def get_global_brain_dir() -> Path:
    """Global brain lives in user-level Claude config."""
    base = Path(os.environ.get("CLAUDE_CONFIG_DIR", os.path.expanduser("~/.claude")))
    return base / "agent-memory" / "pentest-global"


def init(brain_dir: Path):
    dirs = ["waf-profiles", "tech-patterns", "platform-insights", "techniques"]
    for d in dirs:
        (brain_dir / d).mkdir(parents=True, exist_ok=True)

    memory = brain_dir / "MEMORY.md"
    if not memory.exists():
        memory.write_text(f"""# Global Pentest Brain
Initialized: {datetime.now().strftime('%Y-%m-%d')}

Universal knowledge that applies across all engagements.

## WAF Profiles
(learned from engagements)

## Tech Stack Patterns
(tech → common vulns mappings)

## Platform Insights
(what programs actually pay for)

## Universal Techniques
(bypass techniques that work everywhere)
""")
    print(f"✅ Global brain initialized at {brain_dir}")


def learn(brain_dir: Path, category: str, knowledge: str):
    valid = {"waf": "waf-profiles", "tech": "tech-patterns", "platform": "platform-insights", "technique": "techniques"}
    if category not in valid:
        print(f"Unknown category. Valid: {', '.join(valid.keys())}")
        sys.exit(1)

    target_dir = brain_dir / valid[category]
    target_dir.mkdir(parents=True, exist_ok=True)

    log_file = target_dir / "learned.md"
    with open(log_file, "a") as f:
        f.write(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M')}] {knowledge}\n")
    print(f"🧠 Learned ({category}): {knowledge[:80]}...")


def query(brain_dir: Path, topic: str):
    """Search global brain for a topic."""
    results = []
    for md_file in brain_dir.rglob("*.md"):
        content = md_file.read_text()
        if topic.lower() in content.lower():
            # Extract matching lines with context
            for i, line in enumerate(content.splitlines()):
                if topic.lower() in line.lower():
                    results.append((str(md_file.relative_to(brain_dir)), line.strip()))

    if results:
        print(f"\n🔍 Global brain results for '{topic}':")
        for path, line in results[:20]:
            print(f"  [{path}] {line}")
    else:
        print(f"  No global knowledge found for '{topic}'")


def _file_hash(path: Path) -> str:
    """Quick hash for incremental sync (O10)."""
    import hashlib
    return hashlib.md5(path.read_bytes()).hexdigest() if path.exists() else ""


def sync_from_local(brain_dir: Path):
    """Import learnings from local brain to global. Skips unchanged files (O10)."""
    local_brain = Path(".claude/agent-memory-local/brain")
    if not local_brain.exists():
        print("No local brain found.")
        return

    imported = 0
    skipped = 0
    timestamp = datetime.now().strftime('%Y-%m-%d')

    # Load sync hashes for incremental sync (O10)
    hash_file = brain_dir / ".sync-hashes.json"
    import json as _json
    prev_hashes = _json.loads(hash_file.read_text()) if hash_file.exists() else {}
    new_hashes = {}

    # Map of local brain paths → global brain destinations
    sync_map = {
        # Techniques
        "techniques/waf-bypasses.md": "waf-profiles/learned.md",
        "techniques/effective.md": "techniques/learned.md",
        "techniques/exhausted.md": "techniques/exhausted.md",
        # Patterns
        "patterns/platform-responses.md": "platform-insights/learned.md",
        "patterns/false-positives.md": "tech-patterns/false-positives.md",
        "patterns/tech-stack-vulns.md": "tech-patterns/tech-stack-vulns.md",
    }

    for local_rel, global_rel in sync_map.items():
        src = local_brain / local_rel
        if not src.exists():
            continue
        content = src.read_text().strip()
        # Skip files that only have a markdown header (no real data)
        lines = [l for l in content.splitlines() if l.strip() and not l.startswith("#")]
        if not lines:
            continue
        # O10: Skip if unchanged
        h = _file_hash(src)
        new_hashes[local_rel] = h
        if prev_hashes.get(local_rel) == h:
            skipped += 1
            continue
        dest = brain_dir / global_rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "a") as f:
            f.write(f"\n--- Imported {timestamp} ---\n{content}\n")
        imported += 1

    # Import all target files
    targets_dir = local_brain / "targets"
    if targets_dir.exists():
        for target_file in targets_dir.glob("*.md"):
            content = target_file.read_text().strip()
            lines = [l for l in content.splitlines() if l.strip() and not l.startswith("#")]
            if not lines:
                continue
            dest = brain_dir / "tech-patterns" / f"target-{target_file.name}"
            dest.parent.mkdir(parents=True, exist_ok=True)
            with open(dest, "a") as f:
                f.write(f"\n--- Imported {timestamp} from {target_file.name} ---\n{content}\n")
            imported += 1

    # Import session summary (latest session only)
    sessions_dir = local_brain / "sessions"
    if sessions_dir.exists():
        sessions = sorted(sessions_dir.glob("*.md"), reverse=True)
        if sessions:
            latest = sessions[0]
            content = latest.read_text().strip()
            lines = [l for l in content.splitlines() if l.strip() and not l.startswith("#")]
            if lines:
                dest = brain_dir / "techniques" / "session-history.md"
                dest.parent.mkdir(parents=True, exist_ok=True)
                with open(dest, "a") as f:
                    f.write(f"\n--- Session {latest.stem} ---\n{content}\n")
                imported += 1

    # Save sync hashes (O10)
    new_hashes.update({k: v for k, v in prev_hashes.items() if k not in new_hashes})
    hash_file.write_text(_json.dumps(new_hashes, indent=2))
    skip_msg = f", {skipped} unchanged" if skipped else ""
    print(f"📤 Imported {imported} knowledge files from local brain to global{skip_msg}")


def sync_to_local(brain_dir: Path):
    """Export relevant global knowledge to local brain."""
    local_brain = Path(".claude/agent-memory-local/brain")
    if not local_brain.exists():
        print("No local brain found. Run /brain init first.")
        return

    exported = 0
    global_knowledge = brain_dir / "MEMORY.md"
    if global_knowledge.exists():
        dest = local_brain / "patterns" / "global-knowledge.md"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(f"# Global Knowledge (synced {datetime.now().strftime('%Y-%m-%d')})\n\n" + global_knowledge.read_text())
        exported += 1

    for subdir in ["waf-profiles", "techniques"]:
        src = brain_dir / subdir / "learned.md"
        if src.exists() and src.stat().st_size > 10:
            dest = local_brain / "patterns" / f"global-{subdir}.md"
            dest.write_text(src.read_text())
            exported += 1

    print(f"📥 Exported {exported} global knowledge files to local brain")


def stats(brain_dir: Path):
    if not brain_dir.exists():
        print("Global brain not initialized. Run: python3 tools/global_brain.py init")
        return

    total_files = sum(1 for _ in brain_dir.rglob("*.md"))
    total_size = sum(f.stat().st_size for f in brain_dir.rglob("*.md"))
    print(f"\n🧠 Global Brain Stats")
    print(f"   Location: {brain_dir}")
    print(f"   Files: {total_files}")
    print(f"   Size: {total_size / 1024:.1f} KB")
    for subdir in ["waf-profiles", "tech-patterns", "platform-insights", "techniques"]:
        p = brain_dir / subdir
        if p.exists():
            count = sum(1 for _ in p.glob("*.md"))
            print(f"   {subdir}: {count} files")


def main():
    parser = argparse.ArgumentParser(description="Global cross-engagement knowledge base")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("init")
    sub.add_parser("stats")
    sub.add_parser("sync-from-local", help="Import local brain learnings to global")
    sub.add_parser("sync-to-local", help="Export global knowledge to local brain")

    learn_p = sub.add_parser("learn")
    learn_p.add_argument("category", choices=["waf", "tech", "platform", "technique"])
    learn_p.add_argument("knowledge")

    query_p = sub.add_parser("query")
    query_p.add_argument("topic")

    args = parser.parse_args()
    brain_dir = get_global_brain_dir()

    if args.command == "init":
        init(brain_dir)
    elif args.command == "stats":
        stats(brain_dir)
    elif args.command == "learn":
        learn(brain_dir, args.category, args.knowledge)
    elif args.command == "query":
        query(brain_dir, args.topic)
    elif args.command == "sync-from-local":
        sync_from_local(brain_dir)
    elif args.command == "sync-to-local":
        sync_to_local(brain_dir)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
