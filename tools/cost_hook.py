#!/usr/bin/env python3
"""
cost_hook.py — Claude Code hook for automatic cost tracking.

Receives hook event JSON via stdin from Claude Code's hook system.
Supports: SubagentStop, Stop (session end).

Configured in .claude/settings.json under "hooks".
"""

import json
import sys
from datetime import datetime
from pathlib import Path

COST_LOG = Path("cost-tracking.json")

# Pricing per 1M tokens (approximate, 2026)
PRICING = {
    "haiku": {"input": 0.25, "output": 1.25},
    "sonnet": {"input": 3.00, "output": 15.00},
    "opus": {"input": 15.00, "output": 75.00},
}


def load_db() -> dict:
    if COST_LOG.exists():
        try:
            return json.loads(COST_LOG.read_text())
        except:
            pass
    return {"entries": [], "sessions": [], "metadata": {"created": datetime.now().isoformat()}}


def save_db(db: dict):
    db["metadata"]["updated"] = datetime.now().isoformat()
    COST_LOG.write_text(json.dumps(db, indent=2))


def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return
        data = json.loads(raw)
    except:
        return

    event = data.get("hook_event_name", "")
    db = load_db()

    if event == "SubagentStop":
        agent_type = data.get("agent_type", "unknown")
        agent_id = data.get("agent_id", "")
        transcript = data.get("agent_transcript_path", "")

        entry = {
            "ts": datetime.now().isoformat(),
            "event": "agent_complete",
            "agent": agent_type,
            "agent_id": agent_id,
            "session_id": data.get("session_id", ""),
        }
        db["entries"].append(entry)
        save_db(db)

    elif event == "Stop" or event == "SessionEnd":
        entry = {
            "ts": datetime.now().isoformat(),
            "event": "session_end",
            "session_id": data.get("session_id", ""),
        }
        db["sessions"].append(entry)
        save_db(db)


if __name__ == "__main__":
    main()
