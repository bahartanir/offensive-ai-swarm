#!/usr/bin/env python3
"""
cvss_version_guard.py — Claude Code PreToolUse hook.

Blocks Write/Edit on report files that use CVSS:4.0 vectors when the workspace
scope.yaml platform is HackerOne. H1 does not support CVSS 4.0 and will
auto-reject the submission form; CLAUDE.md's CVSS Version Policy pins H1 to
CVSS 3.1 and all other platforms to CVSS 4.0.

Called from .claude/settings.json PreToolUse.Write|Edit.
Stdin: Claude Code hook event JSON.
Stdout: empty (allow) or a decision:block object (deny with message).
Exit code: always 0.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# Match "CVSS:4.0/" (case-insensitive). Catches full vectors like
# CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H
_CVSS_4_RE = re.compile(r"CVSS:4\.0/", re.IGNORECASE)

# scope.yaml is free-form enough that we match the `platform:` line with a
# simple top-level key regex rather than pulling in a YAML dep.
_PLATFORM_RE = re.compile(r"^platform:\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE)

_REPORT_MARKERS = ("reports/", "findings/", "/report.md", "-report.md")


def is_report_target(file_path: str) -> bool:
    return any(marker in file_path for marker in _REPORT_MARKERS)


def platform_from_scope(scope_path: Path) -> str | None:
    if not scope_path.exists():
        return None
    try:
        text = scope_path.read_text()
    except OSError:
        return None
    match = _PLATFORM_RE.search(text)
    if not match:
        return None
    return match.group(1).strip().strip('"').strip("'").lower()


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


def main() -> int:
    payload = read_payload()
    if not payload:
        return 0

    if payload.get("tool_name") not in ("Write", "Edit"):
        return 0

    tool_input = payload.get("tool_input") or {}
    target = tool_input.get("file_path", "")
    if not is_report_target(target):
        return 0

    content = tool_input.get("content") or tool_input.get("new_string") or ""
    if not _CVSS_4_RE.search(content):
        return 0

    platform = platform_from_scope(Path.cwd() / "scope.yaml")
    # Only block when we're confident the platform is HackerOne. Absent or
    # unknown platform -> allow (we don't want to block non-H1 workspaces that
    # happen to mention CVSS 4.0 in passing).
    if platform != "hackerone":
        return 0

    reason = (
        "BLOCKED: HackerOne does not accept CVSS 4.0 vectors. Per CLAUDE.md "
        "CVSS Version Policy, H1 reports must use CVSS:3.1/... vectors. "
        "Rescore with CVSS 3.1 (drop AT/VC/VI/VA/SC/SI/SA; add S:U or S:C "
        "and C:/I:/A:) before writing this report."
    )
    sys.stdout.write(json.dumps({"decision": "block", "reason": reason}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
