#!/usr/bin/env python3
"""
scope_hook.py — Claude Code PreToolUse hook for Bash commands.

Blocks commands that reference out-of-scope targets per the engagement's
scope.yaml / .scope.txt / SCOPE.md. Reuses scope_check.py's matching logic
so wildcard and exact rules are evaluated correctly (unlike plain substring
grep, which blocks `api.robinhood.com` when `vgs-api.robinhood.com` is in
out_of_scope).

Called from .claude/settings.json PreToolUse.Bash.
Stdin:  Claude Code hook event JSON.
Stdout: empty (allow) or a decision:block JSON object (deny with message).
Exit code: always 0 (hook protocol signals block via stdout JSON).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

HOOK_DIR = Path(__file__).resolve().parent
if str(HOOK_DIR) not in sys.path:
    sys.path.insert(0, str(HOOK_DIR))

from scope_check import check_scope, find_scope_file  # noqa: E402

_URL_RE = re.compile(r"https?://([A-Za-z0-9.\-]+)(?::\d+)?", re.IGNORECASE)


def read_payload() -> dict | None:
    try:
        raw = sys.stdin.read()
    except Exception:
        return None
    if not raw.strip():
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def extract_hosts(command: str) -> list[str]:
    """Return every unique hostname appearing in a URL in the command."""
    seen: set[str] = set()
    hosts: list[str] = []
    for match in _URL_RE.finditer(command):
        host = match.group(1).rstrip(".").lower()
        if host and host not in seen:
            seen.add(host)
            hosts.append(host)
    return hosts


def main() -> int:
    payload = read_payload()
    if not payload:
        return 0
    if payload.get("tool_name") not in (None, "Bash"):
        return 0

    command = (payload.get("tool_input") or {}).get("command", "") or ""
    hosts = extract_hosts(command)
    if not hosts:
        return 0

    scope = find_scope_file()
    if scope is None:
        return 0

    for host in hosts:
        verdict = check_scope(host, scope)
        if verdict.get("status") == "OUT_OF_SCOPE":
            rule = verdict.get("matched_rule") or host
            source = verdict.get("source", "scope file")
            reason = (
                f"BLOCKED: {host} is OUT OF SCOPE "
                f"(matched rule: {rule}, source: {source}). "
                "If this is a false positive, inspect the scope file — "
                "wildcard and exact rules are evaluated, not substrings."
            )
            sys.stdout.write(json.dumps({"decision": "block", "reason": reason}))
            return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
