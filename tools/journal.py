#!/usr/bin/env python3
"""
journal.py — Structured session journal (JSONL).

Logs every action, finding, and decision for /resume continuity.

Usage:
    python3 tools/journal.py log <action> <target> <details>
    python3 tools/journal.py show [--target target] [--action hunt|validate|submit]
    python3 tools/journal.py summary
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

JOURNAL_PATH = Path("journal.jsonl")


def log_entry(action: str, target: str, details: str, finding_id: str = "",
              endpoint: str = "", vuln_class: str = "", result: str = ""):
    entry = {
        "ts": datetime.now().isoformat(),
        "action": action,
        "target": target,
        "details": details,
        "finding_id": finding_id,
        "endpoint": endpoint,
        "vuln_class": vuln_class,
        "result": result,
    }
    with open(JOURNAL_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"📓 [{action}] {target}: {details}")


def show_journal(target_filter: str = "", action_filter: str = "", limit: int = 50):
    if not JOURNAL_PATH.exists():
        print("No journal entries yet.")
        return

    entries = []
    for line in JOURNAL_PATH.read_text().splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        if target_filter and target_filter not in e.get("target", ""):
            continue
        if action_filter and action_filter != e.get("action", ""):
            continue
        entries.append(e)

    for e in entries[-limit:]:
        ts = e["ts"][:16]
        print(f"  [{ts}] {e['action']:12s} {e['target']:25s} {e['details'][:60]}")


def summary():
    if not JOURNAL_PATH.exists():
        print("No journal entries yet.")
        return

    actions = {}
    targets = set()
    findings = 0
    for line in JOURNAL_PATH.read_text().splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        actions[e["action"]] = actions.get(e["action"], 0) + 1
        targets.add(e.get("target", ""))
        if e.get("result") in ("confirmed", "pass", "vulnerable"):
            findings += 1

    total = sum(actions.values())
    print(f"📓 Journal Summary")
    print(f"   Total entries: {total}")
    print(f"   Targets: {len(targets)}")
    print(f"   Confirmed findings: {findings}")
    print(f"   By action:")
    for action, count in sorted(actions.items(), key=lambda x: -x[1]):
        print(f"     {action}: {count}")


def main():
    parser = argparse.ArgumentParser(description="Session journal")
    sub = parser.add_subparsers(dest="command")

    log_p = sub.add_parser("log", help="Log an action")
    log_p.add_argument("action", choices=["hunt", "recon", "scan", "validate", "report", "submit", "chain", "triage", "note"])
    log_p.add_argument("target")
    log_p.add_argument("details")
    log_p.add_argument("--finding-id", default="")
    log_p.add_argument("--endpoint", default="")
    log_p.add_argument("--vuln-class", default="")
    log_p.add_argument("--result", default="")

    show_p = sub.add_parser("show", help="Show journal entries")
    show_p.add_argument("--target", default="")
    show_p.add_argument("--action", default="")
    show_p.add_argument("--limit", type=int, default=50)

    sub.add_parser("summary", help="Show journal summary")

    args = parser.parse_args()
    if args.command == "log":
        log_entry(args.action, args.target, args.details, args.finding_id, args.endpoint, args.vuln_class, args.result)
    elif args.command == "show":
        show_journal(args.target, args.action, args.limit)
    elif args.command == "summary":
        summary()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
