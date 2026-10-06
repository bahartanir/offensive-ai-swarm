#!/usr/bin/env python3
"""
file_path_guard.py — Claude Code PreToolUse hook.

Blocks Write/Edit on report files that reference local paths (screenshots,
PoCs, evidence) which don't exist on disk. Backs up CLAUDE.md's "NEVER
HALLUCINATE FILES" rule with programmatic enforcement so a report can't ship
claiming an attachment that was never written.

Called from .claude/settings.json PreToolUse.Write|Edit.
Stdin: the Claude Code hook event JSON.
Stdout: either empty (allow) or a decision:block object (deny with message).
Exit code: always 0 (hook protocol signals block via stdout JSON).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# Match three kinds of path references in markdown:
#   1. Backticked filenames with interesting extensions: `poc/exploit.html`
#   2. Markdown images:  ![alt](path/to/img.png)
#   3. Markdown links to local artifacts: [label](poc/file.html)
_EXTENSIONS = (
    "html|htm|png|jpg|jpeg|gif|svg|webp|mp4|mov|webm|pdf|txt|json|yaml|yml|"
    "py|sh|js|har|pcap|log"
)
_PATH_RE = re.compile(
    rf"`([^`\s]+?\.(?:{_EXTENSIONS}))`"
    rf"|!\[[^\]]*\]\(([^)\s]+?)\)"
    rf"|\[[^\]]*\]\(([^)\s]+?\.(?:{_EXTENSIONS}))\)"
)

# Report targets this hook should guard. Keep permissive — any path with
# `reports/` in it or ending in `-report.md` / `report.md` counts.
_REPORT_MARKERS = ("reports/", "findings/", "/report.md", "-report.md")


def extract_paths(content: str) -> list[str]:
    paths: list[str] = []
    for match in _PATH_RE.finditer(content):
        for group in match.groups():
            if group:
                paths.append(group)
    return paths


def is_local_path(path: str) -> bool:
    """Filter out URLs and demo-payload absolutes like /etc/passwd."""
    if path.startswith(("http://", "https://", "//", "mailto:", "tel:", "#")):
        return False
    if path.startswith("/") and not path.startswith(
        ("/poc", "/reports", "/evidence", "/recon", "/scans", "/findings")
    ):
        return False
    return True


def is_report_target(file_path: str) -> bool:
    return any(marker in file_path for marker in _REPORT_MARKERS)


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

    # Write carries `content`; Edit carries `new_string`.
    content = tool_input.get("content") or tool_input.get("new_string") or ""
    if not content:
        return 0

    cwd = Path.cwd()
    missing: list[str] = []
    for path in extract_paths(content):
        if not is_local_path(path):
            continue
        # Resolve relative to cwd; absolute paths under recognized prefixes
        # are also resolved so we catch both /poc/x.html and poc/x.html.
        resolved = (cwd / path.lstrip("/")).resolve() if path.startswith("/") else (cwd / path).resolve()
        if not resolved.exists() and path not in missing:
            missing.append(path)

    if missing:
        preview = ", ".join(missing[:5])
        more = "" if len(missing) <= 5 else f" (+{len(missing) - 5} more)"
        reason = (
            f"BLOCKED: report references missing local files: {preview}{more}. "
            "Per CLAUDE.md NEVER HALLUCINATE FILES rule, every referenced artifact "
            "must exist on disk before it can appear in a report. Either create "
            "the files now (Write the PoC/screenshot) or remove the references."
        )
        sys.stdout.write(json.dumps({"decision": "block", "reason": reason}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
