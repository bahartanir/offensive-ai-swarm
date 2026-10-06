#!/usr/bin/env python3
"""
chain_pressure_hook.py — SubagentStop hook that auto-flags feeder findings.

After every subagent run (especially hunter agents), scan findings.json for
new CONFIRMED entries that belong to **feeder classes** (open-redirect, info
disclosure, CORS, CSRF, subdomain-takeover, XXE, file-upload, race condition,
business logic, privilege escalation).

Standalone feeder findings are on the never-submit list — the dollar value
lives in the chain. This hook writes a chain-pending advisory file so the
orchestrator (autopilot, /hunt, /resume) auto-dispatches chain-builder on
the next decision point.

Configured in .claude/settings.json under hooks.SubagentStop.

Output:
- File: .claude/agent-memory-local/chain-pending.md
- Stdout: hookSpecificOutput JSON that surfaces the pending-chain count to
  the orchestrator so it can act on it (or skip in --yolo mode).
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Iterable

PENDING_FILE = Path(".claude/agent-memory-local/chain-pending.md")
FINDINGS_FILE = Path("findings.json")

# Vuln-class fingerprints — title / vuln_type / weakness substrings → class.
# Order matters: more specific first.
FEEDER_CLASSES: dict[str, list[str]] = {
    "open-redirect": ["open redirect", "open-redirect"],
    "cors": ["cors ", "cors-", "cross-origin", "cross origin"],
    "info-disclosure": [
        "info disclosure", "info-disclosure", "information disclosure",
        "information-disclosure", "exposed key", "exposed secret",
        "exposed token", "leaked credential", "secret in", "key in bundle",
    ],
    "csrf": ["csrf", "cross-site request forgery"],
    "subdomain-takeover": ["subdomain takeover", "subdomain-takeover", "dangling cname"],
    "xxe": ["xxe", "xml external entit"],
    "file-upload": ["file upload", "unrestricted upload", "extension bypass"],
    "race-condition": ["race condition", "race-condition", "toctou"],
    "business-logic": ["business logic", "business-logic", "price manipulation", "coupon abuse"],
    "privilege-escalation": ["privilege escalation", "privilege-escalation", "privesc"],
}

# Status values that count as "this finding exists and matters" — exclude
# withdrawn/duplicate/n/a/draft to avoid false positives.
ACTIVE_STATUSES = {
    "confirmed", "potential", "submitted", "triaged", "resolved",
    "reported", "new", "open", "validated",
}


def _read_findings() -> list[dict]:
    """Return a list of finding dicts, normalizing list-vs-dict schemas."""
    if not FINDINGS_FILE.exists():
        return []
    try:
        data = json.loads(FINDINGS_FILE.read_text())
    except json.JSONDecodeError:
        return []
    raw = data.get("findings", [])
    if isinstance(raw, dict):
        # Some workspaces use {id: {...}} schema. Add the id back in.
        out = []
        for fid, body in raw.items():
            if not isinstance(body, dict):
                continue
            entry = dict(body)
            entry.setdefault("id", fid)
            out.append(entry)
        return out
    if isinstance(raw, list):
        return [f for f in raw if isinstance(f, dict)]
    return []


def _classify(finding: dict) -> str | None:
    """Return the feeder class name if this finding looks like a feeder."""
    haystack = " ".join(
        str(finding.get(k, "")).lower()
        for k in ("title", "vuln_type", "weakness", "type", "category")
    )
    if not haystack.strip():
        return None
    for cls, signals in FEEDER_CLASSES.items():
        for sig in signals:
            if sig in haystack:
                return cls
    return None


def _is_active(finding: dict) -> bool:
    """Filter out withdrawn / N-A / dup / draft findings."""
    status = str(finding.get("status", "")).lower().strip()
    if not status:
        # No status = treat as active (probably new).
        return True
    if status in ACTIVE_STATUSES:
        return True
    if any(skip in status for skip in ("withdraw", "duplicate", "n/a", "n-a", "draft", "rejected", "spam")):
        return False
    # Unknown status: be conservative, skip.
    return False


def _has_chain_marker(finding: dict) -> bool:
    """True if the finding already references a chain (chain-id, chained_with, etc)."""
    if any(finding.get(k) for k in ("chain_id", "chained_with", "chain")):
        return True
    notes = str(finding.get("notes", "")).lower() + str(finding.get("description", "")).lower()
    return "chain-candidate" in notes or "chain confirmed" in notes


def _scan_pending(findings: Iterable[dict]) -> list[tuple[str, str, str]]:
    """Return list of (finding_id, class, title) for pending feeder findings."""
    pending: list[tuple[str, str, str]] = []
    for f in findings:
        if not _is_active(f):
            continue
        if _has_chain_marker(f):
            continue
        cls = _classify(f)
        if cls is None:
            continue
        fid = str(f.get("id") or f.get("report_id") or f.get("title", "?"))[:80]
        title = str(f.get("title", ""))[:140]
        pending.append((fid, cls, title))
    return pending


def _write_advisory(pending: list[tuple[str, str, str]]) -> None:
    """Write the chain-pending advisory file."""
    PENDING_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not pending:
        # Empty file (or remove) means nothing pending.
        if PENDING_FILE.exists():
            PENDING_FILE.unlink()
        return
    lines = [
        "# Chain-Pending Findings",
        "",
        f"_Updated: {datetime.now().isoformat(timespec='seconds')}_",
        "",
        "These confirmed findings are in feeder vuln-classes — standalone "
        "they're on the never-submit list. Run `/chain` (or autopilot will "
        "dispatch chain-builder automatically in --paranoid/--normal mode) "
        "to walk the chain anchors from `rules/chain-table.md`.",
        "",
        "| Finding | Feeder class | Title |",
        "|---------|--------------|-------|",
    ]
    for fid, cls, title in pending:
        # Escape pipes in title to keep markdown table valid.
        safe_title = title.replace("|", "\\|")
        lines.append(f"| `{fid}` | {cls} | {safe_title} |")
    PENDING_FILE.write_text("\n".join(lines) + "\n")


def _emit_hook_output(pending_count: int) -> None:
    """Print hookSpecificOutput JSON for Claude Code to consume."""
    if pending_count == 0:
        return
    msg = (
        f"Chain-pressure: {pending_count} feeder finding(s) pending chain. "
        f"See {PENDING_FILE}. Run /chain or rely on autopilot's "
        f"--paranoid/--normal auto-dispatch."
    )
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "SubagentStop",
            "additionalContext": msg,
        }
    }
    print(json.dumps(payload))


def main() -> None:
    # Read+ignore the hook event JSON; we don't need its fields here.
    try:
        sys.stdin.read()
    except Exception:
        pass

    findings = _read_findings()
    pending = _scan_pending(findings)
    _write_advisory(pending)
    _emit_hook_output(len(pending))


if __name__ == "__main__":
    main()
