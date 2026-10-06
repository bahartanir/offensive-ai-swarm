#!/usr/bin/env python3
"""
response_tracker.py — Track platform responses to submissions.

Learns what each program actually pays for vs rejects.
Feeds insights back into the brain.

Usage:
    python3 tools/response_tracker.py log <report_id> <status> [--bounty 500] [--reason "duplicate"]
    python3 tools/response_tracker.py insights [--program handle]
    python3 tools/response_tracker.py avoid    # Show what to stop reporting
"""

import argparse
import json
from datetime import datetime
from pathlib import Path

DB_PATH = Path("response-history.json")


def load_db() -> dict:
    if DB_PATH.exists():
        return json.loads(DB_PATH.read_text())
    return {"reports": [], "insights": {}}


def save_db(db: dict):
    DB_PATH.write_text(json.dumps(db, indent=2))


def log_response(report_id: str, status: str, bounty: float = 0, reason: str = "",
                 vuln_type: str = "", program: str = "", platform: str = ""):
    db = load_db()
    db["reports"].append({
        "report_id": report_id,
        "status": status,  # accepted, duplicate, informative, not-applicable, triaged, resolved
        "bounty": bounty,
        "reason": reason,
        "vuln_type": vuln_type,
        "program": program,
        "platform": platform,
        "timestamp": datetime.now().isoformat(),
    })

    # Update insights
    key = f"{platform}/{program}" if platform and program else "global"
    if key not in db["insights"]:
        db["insights"][key] = {"accepted": {}, "rejected": {}, "duplicates": {}}

    if status in ("accepted", "triaged", "resolved"):
        vt = vuln_type or "unknown"
        db["insights"][key]["accepted"][vt] = db["insights"][key]["accepted"].get(vt, 0) + 1
    elif status == "duplicate":
        vt = vuln_type or "unknown"
        db["insights"][key]["duplicates"][vt] = db["insights"][key]["duplicates"].get(vt, 0) + 1
    elif status in ("informative", "not-applicable"):
        vt = vuln_type or "unknown"
        db["insights"][key]["rejected"][vt] = db["insights"][key]["rejected"].get(vt, 0) + 1

    save_db(db)

    icon = {"accepted": "✅", "triaged": "📋", "resolved": "🎯", "duplicate": "🔄", "informative": "ℹ️", "not-applicable": "❌"}.get(status, "❓")
    bounty_str = f" (${bounty:.0f})" if bounty else ""
    print(f"{icon} Logged: {report_id} → {status}{bounty_str}")

    # F9: Auto-boost paid techniques in global brain
    if status in ("accepted", "triaged", "resolved") and bounty > 0:
        boost_technique(vuln_type, bounty, program, platform)

    # Update brain if available
    brain_patterns = Path(".claude/agent-memory-local/brain/patterns/platform-responses.md")
    if brain_patterns.parent.exists():
        with open(brain_patterns, "a") as f:
            f.write(f"\n[{datetime.now().strftime('%Y-%m-%d')}] {platform}/{program} | {vuln_type} | {status}{bounty_str} {reason}")


def show_insights(program_filter: str = ""):
    db = load_db()
    if not db["reports"]:
        print("No response data yet. Log responses with: response_tracker.py log <id> <status>")
        return

    print("\n📊 Platform Response Insights")

    for key, data in db.get("insights", {}).items():
        if program_filter and program_filter not in key:
            continue
        print(f"\n  Program: {key}")

        if data["accepted"]:
            print("    ✅ Accepted:")
            for vt, count in sorted(data["accepted"].items(), key=lambda x: -x[1]):
                print(f"       {vt}: {count}x")

        if data["duplicates"]:
            print("    🔄 Duplicates (avoid these):")
            for vt, count in sorted(data["duplicates"].items(), key=lambda x: -x[1]):
                print(f"       {vt}: {count}x")

        if data["rejected"]:
            print("    ❌ Rejected:")
            for vt, count in sorted(data["rejected"].items(), key=lambda x: -x[1]):
                print(f"       {vt}: {count}x")

    # Summary
    total = len(db["reports"])
    accepted = sum(1 for r in db["reports"] if r["status"] in ("accepted", "triaged", "resolved"))
    total_bounty = sum(r.get("bounty", 0) for r in db["reports"])
    print(f"\n  Overall: {accepted}/{total} accepted ({accepted/total*100:.0f}%)" if total else "")
    print(f"  Total bounties: ${total_bounty:,.0f}")


def show_avoid():
    """Show vulnerability types with high duplicate/rejection rates."""
    db = load_db()
    print("\n🚫 High Duplicate/Rejection Types (consider avoiding)")
    for key, data in db.get("insights", {}).items():
        dupes = data.get("duplicates", {})
        rejects = data.get("rejected", {})
        avoid = {**dupes}
        for k, v in rejects.items():
            avoid[k] = avoid.get(k, 0) + v
        if avoid:
            print(f"\n  {key}:")
            for vt, count in sorted(avoid.items(), key=lambda x: -x[1]):
                print(f"    {vt}: {count} duplicates/rejections")


def main():
    parser = argparse.ArgumentParser(description="Track platform responses to learn what pays")
    sub = parser.add_subparsers(dest="command")

    log_p = sub.add_parser("log", help="Log a platform response")
    log_p.add_argument("report_id")
    log_p.add_argument("status", choices=["accepted", "duplicate", "informative", "not-applicable", "triaged", "resolved"])
    log_p.add_argument("--bounty", type=float, default=0)
    log_p.add_argument("--reason", default="")
    log_p.add_argument("--vuln-type", default="")
    log_p.add_argument("--program", default="")
    log_p.add_argument("--platform", default="")

    sub.add_parser("insights", help="Show platform response insights").add_argument("--program", default="")
    sub.add_parser("avoid", help="Show types to avoid due to high rejection/duplication")

    args = parser.parse_args()
    if args.command == "log":
        log_response(args.report_id, args.status, args.bounty, args.reason, args.vuln_type, args.program, args.platform)
    elif args.command == "insights":
        show_insights(args.program)
    elif args.command == "avoid":
        show_avoid()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()


# --- F9: Feedback loop — boost paid techniques ---

def boost_technique(vuln_type: str, bounty: float, program: str, platform: str):
    """When a report gets paid, boost that technique's priority in global brain."""
    import subprocess
    if bounty > 0 and vuln_type:
        knowledge = f"{platform}/{program}: {vuln_type} paid ${bounty:.0f}"
        subprocess.run([
            "python3", "tools/global_brain.py", "learn", "technique", knowledge
        ], capture_output=True)
        print(f"🔄 Boosted technique: {vuln_type} (${bounty:.0f} on {program})")
