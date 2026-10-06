#!/usr/bin/env python3
"""
cost.py — Token cost tracking for pentest engagements.

Tracks estimated costs per agent, per target, per session.
Integrates with brain session logs.

Usage:
    python3 tools/cost.py log <agent> <model> <input_tokens> <output_tokens>
    python3 tools/cost.py summary
    python3 tools/cost.py roi        # Compare cost vs estimated bounty value
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

# Approximate pricing per 1M tokens (as of 2026)
PRICING = {
    "haiku": {"input": 0.25, "output": 1.25},
    "sonnet": {"input": 3.00, "output": 15.00},
    "opus": {"input": 15.00, "output": 75.00},
}
COST_DB = Path("cost-tracking.json")


def load_db() -> dict:
    if COST_DB.exists():
        return json.loads(COST_DB.read_text())
    return {"entries": [], "metadata": {"created": datetime.now().isoformat()}}


def save_db(db: dict):
    db["metadata"]["updated"] = datetime.now().isoformat()
    COST_DB.write_text(json.dumps(db, indent=2))


def log_cost(agent: str, model: str, input_tokens: int, output_tokens: int):
    db = load_db()
    model_key = model.lower()
    if model_key not in PRICING:
        model_key = "opus"  # Default assumption (orchestrator runs on opus)

    p = PRICING[model_key]
    cost = (input_tokens * p["input"] + output_tokens * p["output"]) / 1_000_000

    entry = {
        "timestamp": datetime.now().isoformat(),
        "agent": agent,
        "model": model_key,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cost_usd": round(cost, 6),
    }
    db["entries"].append(entry)
    save_db(db)
    print(f"💰 Logged: {agent} ({model_key}) — {input_tokens}+{output_tokens} tokens = ${cost:.4f}")


def summary():
    db = load_db()
    if not db["entries"]:
        print("No cost data yet.")
        return

    total = sum(e["cost_usd"] for e in db["entries"])
    by_agent = {}
    by_model = {}
    for e in db["entries"]:
        by_agent[e["agent"]] = by_agent.get(e["agent"], 0) + e["cost_usd"]
        by_model[e["model"]] = by_model.get(e["model"], 0) + e["cost_usd"]

    print(f"\n💰 Cost Summary")
    print(f"   Total: ${total:.4f}")
    print(f"   Entries: {len(db['entries'])}")
    print(f"\n   By Agent:")
    for agent, cost in sorted(by_agent.items(), key=lambda x: -x[1]):
        print(f"     {agent}: ${cost:.4f}")
    print(f"\n   By Model:")
    for model, cost in sorted(by_model.items(), key=lambda x: -x[1]):
        print(f"     {model}: ${cost:.4f}")


def roi():
    db = load_db()
    total_cost = sum(e["cost_usd"] for e in db["entries"])

    # Read findings to estimate bounty value
    findings_path = Path("findings.json")
    estimated_bounty = 0
    if findings_path.exists():
        findings = json.loads(findings_path.read_text()).get("findings", {})
        bounty_est = {"critical": 5000, "high": 2500, "medium": 750, "low": 200}
        for f in findings.values():
            if f.get("status") in ("confirmed", "reported"):
                sev = f.get("severity", "medium").lower()
                estimated_bounty += bounty_est.get(sev, 200)

    print(f"\n📊 ROI Estimate")
    print(f"   Total cost: ${total_cost:.2f}")
    print(f"   Estimated bounty: ${estimated_bounty:,.0f}")
    if total_cost > 0:
        print(f"   ROI: {estimated_bounty / total_cost:.0f}x")
    else:
        print(f"   ROI: N/A (no costs logged)")


def main():
    parser = argparse.ArgumentParser(description="Cost tracking for pentest engagements")
    sub = parser.add_subparsers(dest="command")

    log_p = sub.add_parser("log", help="Log a cost entry")
    log_p.add_argument("agent")
    log_p.add_argument("model")
    log_p.add_argument("input_tokens", type=int)
    log_p.add_argument("output_tokens", type=int)

    sub.add_parser("summary", help="Show cost summary")
    sub.add_parser("roi", help="Show ROI estimate")

    args = parser.parse_args()
    if args.command == "log":
        log_cost(args.agent, args.model, args.input_tokens, args.output_tokens)
    elif args.command == "summary":
        summary()
    elif args.command == "roi":
        roi()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
