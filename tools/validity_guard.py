#!/usr/bin/env python3
"""
validity_guard.py — PreToolUse hook for Write/Edit on report drafts.

Blocks the agent from writing a draft that contains never-submit-list
signals without a chain. Fires when the file path looks like a report
draft (`reports/drafts/*.md`, `reports/*.md`, `*report*.md`) and the
content matches one of the never-submit patterns.

Behavior:
- DENY (block + suggest chain anchor) when the draft hits a never-submit
  signal AND no chain language is present in the body.
- ALLOW when the draft includes a chain narrative.
- ALLOW for non-report files.

The agent gets the chain anchor from rules/chain-table.md as part of
the deny message — turning an N/A submission into a chain-build prompt.

Configured in .claude/settings.json under hooks.PreToolUse with
matcher "Write|Edit".
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# Substrings in the draft that indicate it's a candidate for blocking.
# These align with rules/never-submit.md.
NEVER_SUBMIT_SIGNALS: dict[str, str] = {
    "open redirect": (
        "open-redirect → OAuth redirect_uri reflection / returnTo / SAML "
        "RelayState / login-flow CSRF / cookie tossing prerequisite "
        "(rules/chain-table.md → Per-Class Chain Anchors → open-redirect)"
    ),
    "open-redirect": (
        "open-redirect → OAuth redirect_uri reflection / returnTo / SAML "
        "RelayState / login-flow CSRF / cookie tossing prerequisite"
    ),
    "cors wildcard": (
        "cors → credentialed authenticated endpoint required for exfil; "
        "see rules/chain-table.md → Per-Class Chain Anchors → cors"
    ),
    "cors misconfig": (
        "cors → credentialed authenticated endpoint required for exfil"
    ),
    "graphql introspection": (
        "graphql introspection alone is informational. Pair with auth "
        "bypass on mutations / sensitive query exposure to be reportable."
    ),
    "self-xss": (
        "self-xss → not reportable alone. Chain via CSRF-delivered or "
        "social-delivery path with non-trivial victim payoff."
    ),
    "missing security header": (
        "missing security headers (CSP / HSTS / X-Frame-Options) alone "
        "are on the never-submit list."
    ),
    "missing csp": (
        "missing CSP alone is on the never-submit list. Pair with XSS "
        "(amplifier) for reportable impact."
    ),
    "missing cookie flag": (
        "missing cookie flags (HttpOnly / Secure / SameSite) alone are "
        "on the never-submit list."
    ),
    "logout csrf": (
        "logout CSRF alone is informational. Not on the never-submit list."
    ),
    "missing dmarc": "missing SPF/DKIM/DMARC alone is on the never-submit list.",
    "missing spf": "missing SPF/DKIM/DMARC alone is on the never-submit list.",
    "missing dkim": "missing SPF/DKIM/DMARC alone is on the never-submit list.",
    "ssrf via dns": (
        "SSRF DNS-only callback alone is informational. Pair with "
        "internal data exfil / cloud metadata access to be reportable."
    ),
    "blind ssrf": (
        "Blind SSRF with only DNS callback proof is informational. "
        "Demonstrate response body from an internal service or cloud "
        "metadata to upgrade severity."
    ),
    "rate limit": (
        "Rate-limit on non-critical endpoint is on the never-submit list."
    ),
    "clickjack": (
        "Clickjacking without a state-changing PoC is informational."
    ),
    "version disclosure": (
        "Banner / version disclosure alone is on the never-submit list. "
        "Pair with a known-CVE exploit for reportable impact."
    ),
    "user enumeration": (
        "User enumeration via response delta alone is typically "
        "informational unless paired with no-rate-limit + privacy impact."
    ),
}

# Phrases that indicate the draft already includes a chain narrative.
# If any of these are present, allow the write — the author is doing
# the chain work properly.
CHAIN_PRESENT_SIGNALS = [
    "chain:",
    "chain-candidate",
    "chained with",
    "→ ato",
    "-> ato",
    "→ rce",
    "-> rce",
    "→ admin",
    "-> admin",
    "leads to account takeover",
    "results in account takeover",
    "enables account takeover",
    "enables admin",
    "exfiltrate",
    "cloud metadata",
    "169.254.169.254",
    "imds",
    "credentialed exfil",
    "cross-tenant",
    "cross tenant",
    "parent domain cookie",
    "cookie tossing",
    "session theft",
    "token theft",
]


def _looks_like_report(path: str) -> bool:
    """Heuristic: is this file a vulnerability report draft?"""
    p = path.lower()
    if not p.endswith((".md", ".markdown")):
        return False
    return (
        "/reports/drafts/" in p
        or "/reports/" in p
        or "/reports-drafts/" in p
        or "/findings/" in p
        or p.endswith("/finding.md")
        or p.endswith("/report.md")
        or "/draft" in p
    )


def _scan(content: str) -> tuple[str | None, str | None]:
    """Return (matched_signal, chain_anchor_msg) or (None, None) if clean."""
    body = content.lower()
    # Already chained? Pass-through.
    for marker in CHAIN_PRESENT_SIGNALS:
        if marker in body:
            return None, None
    # Never-submit signal present without chain language?
    for signal, anchor in NEVER_SUBMIT_SIGNALS.items():
        if signal in body:
            return signal, anchor
    return None, None


def _deny(signal: str, anchor: str, path: str) -> dict:
    msg = (
        f"validity_guard: blocked write to {path}\n\n"
        f"Detected never-submit signal: '{signal}'\n\n"
        f"This finding pattern is on rules/never-submit.md and won't pass "
        f"validator. Chain anchor needed:\n\n  {anchor}\n\n"
        f"To proceed, either:\n"
        f"  (a) Add the chain narrative to the draft (chain target, "
        f"impact, repro for the chained behavior), OR\n"
        f"  (b) Run /chain to walk the chain anchors first, then come "
        f"back with the chain confirmed, OR\n"
        f"  (c) If you've intentionally chained this and the guard is "
        f"missing the marker, add 'chained with X', 'enables ATO', or "
        f"another chain phrase from validity_guard.py to the draft."
    )
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": msg,
        }
    }


def main() -> None:
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return
        data = json.loads(raw)
    except Exception:
        return

    tool = data.get("tool_name", "")
    if tool not in ("Write", "Edit", "MultiEdit"):
        return

    inp = data.get("tool_input", {}) or {}
    path = str(inp.get("file_path", ""))
    if not path or not _looks_like_report(path):
        return

    # Get the content the agent is trying to write.
    content = ""
    if tool == "Write":
        content = str(inp.get("content", ""))
    elif tool == "Edit":
        content = str(inp.get("new_string", ""))
    elif tool == "MultiEdit":
        for edit in inp.get("edits", []) or []:
            content += str(edit.get("new_string", "")) + "\n"

    if not content.strip():
        return

    signal, anchor = _scan(content)
    if signal is None:
        return

    print(json.dumps(_deny(signal, anchor or "", path)))


if __name__ == "__main__":
    main()
