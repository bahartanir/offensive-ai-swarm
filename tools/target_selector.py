#!/usr/bin/env python3
"""
target_selector.py — Rank programs by hunting ROI.

Factors: bounty range, competition level, your past success, tech stack match.

Usage:
    python3 tools/target_selector.py rank program1 program2 program3
    python3 tools/target_selector.py suggest   # based on global brain patterns
"""

import argparse
import json
import sys
from pathlib import Path


def estimate_roi(program: str) -> dict:
    """Estimate ROI for a program based on available data."""
    workspace = Path.home() / "bounties"
    score = 50  # base score

    # Check if we have a workspace (past engagement)
    matches = list(workspace.glob(f"*-{program}"))
    has_history = len(matches) > 0

    findings_count = 0
    bounty_earned = 0

    if has_history:
        ws = matches[0]
        # Check findings
        findings_file = ws / "findings.json"
        if findings_file.exists():
            try:
                data = json.loads(findings_file.read_text())
                findings_count = len(data.get("findings", {}))
                score += findings_count * 5
            except:
                pass

        # Check response history
        resp_file = ws / "response-history.json"
        if resp_file.exists():
            try:
                data = json.loads(resp_file.read_text())
                for r in data.get("reports", []):
                    bounty_earned += r.get("bounty", 0)
                    if r["status"] in ("accepted", "resolved"):
                        score += 10
                    elif r["status"] == "duplicate":
                        score -= 5
            except:
                pass

        # Check hacktivity for payout signals
        hacktivity = ws / "hacktivity.md"
        if hacktivity.exists():
            content = hacktivity.read_text()
            # Count disclosed reports (more = more active = more competition but also more surface)
            report_count = content.count("- [")
            if report_count < 20:
                score += 15  # low competition
            elif report_count > 100:
                score -= 10  # high competition

    return {
        "program": program,
        "score": score,
        "has_history": has_history,
        "findings": findings_count,
        "bounty_earned": bounty_earned,
    }


def rank_programs(programs: list[str]):
    """Rank programs by estimated ROI."""
    results = [estimate_roi(p) for p in programs]
    results.sort(key=lambda x: -x["score"])

    print("🎯 Program Ranking (by estimated ROI)")
    print(f"{'#':<4} {'Program':<25} {'Score':<8} {'History':<10} {'Findings':<10} {'Earned'}")
    print("─" * 75)
    for i, r in enumerate(results, 1):
        history = "✅" if r["has_history"] else "new"
        print(f"{i:<4} {r['program']:<25} {r['score']:<8} {history:<10} {r['findings']:<10} ${r['bounty_earned']:,.0f}")


def suggest():
    """Suggest programs based on global brain patterns."""
    global_brain = Path.home() / ".claude" / "agent-memory" / "pentest-global"
    if not global_brain.exists():
        print("No global brain data. Hunt some programs first.")
        return

    print("🎯 Suggestions based on global brain patterns:")
    tech_file = global_brain / "techniques" / "learned.md"
    if tech_file.exists():
        content = tech_file.read_text()
        print(f"   Effective techniques found: {content.count('---')}")
        # Show most recent learnings
        for line in content.splitlines()[-10:]:
            if line.strip() and not line.startswith("#") and not line.startswith("---"):
                print(f"   {line.strip()}")
    else:
        print("   No technique data yet. Complete some engagements first.")


def main():
    parser = argparse.ArgumentParser(description="Program ROI ranking")
    sub = parser.add_subparsers(dest="command")

    rank_p = sub.add_parser("rank", help="Rank programs by ROI")
    rank_p.add_argument("programs", nargs="+")

    sub.add_parser("suggest", help="Suggest programs from global brain")

    args = parser.parse_args()
    if args.command == "rank":
        rank_programs(args.programs)
    elif args.command == "suggest":
        suggest()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
