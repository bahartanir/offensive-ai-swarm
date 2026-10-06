#!/usr/bin/env python3
"""Hacktivity intelligence extraction + autonomy-first ranking engine.

Analyzes disclosed reports to find patterns:
* what vuln classes get paid (regex-based classification, not substring)
* what programs pay best (ROI per class: avg + max + count)
* what endpoints are common targets (path hotspots from titles)

Also generates a structured test matrix so autopilot/hunt loops can expand
from single-payload probing to a Cartesian exploration across vectors,
encodings, and bypass families.

Usage:
    python3 tools/intel_engine.py analyze
    python3 tools/intel_engine.py patterns
    python3 tools/intel_engine.py suggest "<tech-stack>"
    python3 tools/intel_engine.py matrix <vuln-class> [--limit N]

Autonomy-first subcommands (wired into /autopilot, /hunt, validator, chain-builder):
    classes            — ranked vuln-class hypotheses from tech + hacktivity ROI + brain
    rank-surface       — score endpoints into P1/P2/Kill buckets
    record-outcome     — update adaptive telemetry with one hunt outcome
    budget             — allocate minutes/tokens across ranked classes
    exhaustion-gate    — enforce quality floor before marking a class exhausted
    chain-plan         — capability-graph-driven next-bug suggestions
    evidence-score     — pre-report evidence sufficiency gate

JSON output schemas (load-bearing — agent prompts parse these fields):
    classes      → list[{vuln_class, display, score, exhausted, reasons[]}]
    rank-surface → list[{endpoint, score, bucket, reasons[]}]
    budget       → list[{vuln_class, display, budget_minutes, budget_tokens, score}]
    chain-plan   → list[{from_capability, next_bug, gained_capability, terminal_impact, priority}]
    evidence-score → {score, decision, notes[]}
    exhaustion-gate → {ok, reason}

Any rename in the above breaks agent parsers. Update both ends together.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Absolute import so tools/ can be run from any CWD.
_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from file_safety import atomic_write_text, load_json_or_quarantine, locked_file  # noqa: E402


SEVERITY_ALIASES = {
    "crit": "critical",
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "med": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "none": "none",
}

# Regex patterns for vuln class detection in report titles. Each pattern is a
# word-boundary match — avoids the old bug where "rce" in "forcefully" counted.
VULN_PATTERNS = {
    "IDOR": [
        r"\bidor\b",
        r"insecure direct object",
        r"broken object[- ]level",
        r"\bbola\b",
    ],
    "XSS": [r"\bxss\b", r"cross[\s-]?site scripting", r"dom[\s-]?based"],
    "SSRF": [r"\bssrf\b", r"server[\s-]?side request forgery"],
    "SQLi": [r"\bsqli\b", r"sql injection"],
    "CSRF": [r"\bcsrf\b", r"cross[\s-]?site request forgery"],
    "RCE": [r"\brce\b", r"remote code execution", r"command injection"],
    "SSTI": [r"\bssti\b", r"template injection"],
    "Auth Bypass": [
        r"auth(?:entication)? bypass",
        r"account takeover",
        r"\bato\b",
        r"password reset",
    ],
    "Open Redirect": [r"open redirect"],
    "GraphQL": [r"graphql"],
    "Race Condition": [r"race condition", r"time[\s-]?of[\s-]?check", r"\btoctou\b"],
    "XXE": [r"\bxxe\b", r"xml external entity"],
    "File Upload": [r"file upload", r"unrestricted upload", r"arbitrary file (?:write|upload)"],
    "Info Disclosure": [
        r"info(?:rmation)? disclosure",
        r"data leak",
        r"sensitive data exposure",
        r"api key leak",
    ],
    "CORS": [r"\bcors\b"],
    "OAuth": [r"\boauth\b", r"\boidc\b", r"\bsaml\b"],
    "Business Logic": [r"business logic", r"workflow bypass", r"logic flaw"],
    "Prototype Pollution": [r"prototype pollution"],
    "Deserialization": [r"deserialization", r"unsafe deserialize", r"insecure deserial"],
    "LFI": [r"\blfi\b", r"local file inclusion", r"path traversal", r"directory traversal"],
}

# Accept $, €, £, ¥ currency markers; allow optional "EUR"/"USD" suffix.
# Normalises short-hand (7.5k, 1.2M) so ROI ranking isn't skewed.
_BOUNTY_RE = re.compile(
    r"""
    [$€£¥]?\s*
    (?P<amount>\d+(?:[.,]\d+)?)
    \s*
    (?P<unit>[kKmM])?
    \s*
    (?:USD|EUR|GBP|JPY)?
    """,
    re.VERBOSE,
)


def _normalize_severity(raw: str) -> str:
    return SEVERITY_ALIASES.get(raw.strip().lower(), raw.strip().lower())


def _parse_bounty(raw: str | None) -> int:
    """Parse a bounty amount supporting currency symbols and k/M shorthand."""
    if not raw:
        return 0
    m = _BOUNTY_RE.search(raw)
    if not m:
        return 0
    amount_str = m.group("amount").replace(",", "")
    try:
        amount = float(amount_str)
    except ValueError:
        return 0
    unit = (m.group("unit") or "").lower()
    factor = {"k": 1_000, "m": 1_000_000}.get(unit, 1)
    return int(amount * factor)


def _extract_vuln_type(title: str) -> str | None:
    t = title.lower()
    for vuln, patterns in VULN_PATTERNS.items():
        if any(re.search(pattern, t) for pattern in patterns):
            return vuln
    return None


# Match paths starting with /, containing typical URL characters, not leading
# to `//` (protocol) or ending on trailing punctuation.
_PATH_RE = re.compile(r"(?<![a-zA-Z/:])(/[A-Za-z0-9_\-./{}:%]+[A-Za-z0-9_}])")


def _extract_paths(text: str) -> list[str]:
    return _PATH_RE.findall(text)


def analyze_hacktivity(hacktivity_path: Path | None = None) -> dict:
    """Extract intelligence from hacktivity data."""
    if hacktivity_path is None:
        hacktivity_path = Path("hacktivity.md")
    if not hacktivity_path.exists():
        print("No hacktivity.md found. Run /sync first.")
        return {}

    content = hacktivity_path.read_text()
    vuln_types: Counter[str] = Counter()
    severities: Counter[str] = Counter()
    payout_by_vuln: dict[str, list[int]] = defaultdict(list)
    endpoint_paths: Counter[str] = Counter()
    bounties: list[dict] = []

    for line in content.splitlines():
        # Parse lines like: - [HIGH] ($5,000) IDOR on /api/users — api.example.com
        m = re.match(r"- \[([A-Za-z]+)\]\s*(?:\(([^)]+)\))?\s*(.*)", line)
        if not m:
            continue
        sev = _normalize_severity(m.group(1))
        bounty = _parse_bounty(m.group(2))
        title = m.group(3)
        severities[sev] += 1
        if bounty > 0:
            bounties.append({"severity": sev, "amount": bounty, "title": title})

        for path in _extract_paths(title):
            endpoint_paths[path] += 1

        vuln = _extract_vuln_type(title)
        if vuln:
            vuln_types[vuln] += 1
            if bounty > 0:
                payout_by_vuln[vuln].append(bounty)

    vuln_roi = []
    for vuln, amounts in payout_by_vuln.items():
        vuln_roi.append(
            {
                "vuln": vuln,
                "count_paid": len(amounts),
                "avg": int(sum(amounts) / len(amounts)),
                "max": max(amounts),
            }
        )
    vuln_roi.sort(key=lambda x: (x["avg"], x["count_paid"]), reverse=True)

    intel = {
        "total_reports": sum(severities.values()),
        "by_severity": dict(severities),
        "by_vuln_type": dict(vuln_types.most_common()),
        "top_paths": dict(endpoint_paths.most_common(20)),
        "vuln_roi": vuln_roi[:15],
        "bounties": {
            "total": sum(b["amount"] for b in bounties),
            "count": len(bounties),
            "avg": int(sum(b["amount"] for b in bounties) / len(bounties)) if bounties else 0,
            "max": max((b["amount"] for b in bounties), default=0),
        },
    }

    atomic_write_text(Path("intel.json"), json.dumps(intel, indent=2))

    print(f"📊 Hacktivity Intel ({intel['total_reports']} reports)")
    print(
        f"   Bounties: {intel['bounties']['count']} paid, "
        f"avg ${intel['bounties']['avg']:,}, max ${intel['bounties']['max']:,}"
    )
    if vuln_types:
        print("\n   Most reported vuln types:")
        for vt, count in vuln_types.most_common(10):
            print(f"     {vt}: {count}")
    if vuln_roi:
        print("\n   Highest ROI vuln classes (paid reports):")
        for row in vuln_roi[:5]:
            print(
                f"     {row['vuln']}: avg ${row['avg']:,} "
                f"(max ${row['max']:,}, {row['count_paid']} paid)"
            )
    if endpoint_paths:
        print("\n   Most targeted endpoints:")
        for path, count in endpoint_paths.most_common(8):
            print(f"     {path}: {count}")
    print("\n   By severity:")
    for sev in ["critical", "high", "medium", "low", "info"]:
        print(f"     {sev}: {severities.get(sev, 0)}")

    return intel


TECH_VULN_MAP = {
    "rails": ["IDOR", "Mass Assignment", "SSTI"],
    "django": ["IDOR", "SSTI", "Auth Bypass"],
    "flask": ["SSTI", "SSRF", "Path Traversal"],
    "express": ["Prototype Pollution", "Path Traversal", "NoSQL Injection"],
    "next.js": ["SSRF (Server Actions)", "Open Redirect", "Auth Bypass"],
    "spring": ["Actuator Endpoints", "SSTI", "SpEL Injection"],
    "graphql": ["Introspection + Auth Bypass", "IDOR via node()", "Batch DoS"],
    "react": ["DOM XSS", "Prototype Pollution"],
    "php": ["File Upload", "LFI/RFI", "Type Juggling", "SQL Injection"],
    "java": ["Deserialization", "XXE", "SSTI"],
    "golang": ["Path Traversal", "Race Conditions"],
    "postgresql": ["SQL Injection", "COPY FROM PROGRAM RCE"],
    "mongodb": ["NoSQL Injection", "SSRF"],
    "redis": ["SSRF", "Unauthorized Access"],
    "s3": ["Bucket Listing", "Public Write", "Subdomain Takeover"],
    "okta": ["OAuth Misconfiguration", "SAML Bypass"],
    "cloudflare": ["Cache Poisoning", "WAF Bypass"],
}


CANONICAL_VULN_CLASSES = {
    "idor",
    "xss",
    "ssrf",
    "sqli",
    "csrf",
    "rce",
    "ssti",
    "auth-bypass",
    "open-redirect",
    "graphql",
    "race-condition",
    "xxe",
    "file-upload",
    "info-disclosure",
    "cors",
    "oauth",
    "business-logic",
    "prototype-pollution",
    "deserialization",
    "lfi",
}

DISPLAY_NAMES = {
    "idor": "IDOR",
    "xss": "XSS",
    "ssrf": "SSRF",
    "sqli": "SQLi",
    "csrf": "CSRF",
    "rce": "RCE",
    "ssti": "SSTI",
    "auth-bypass": "Auth Bypass",
    "open-redirect": "Open Redirect",
    "graphql": "GraphQL",
    "race-condition": "Race Condition",
    "xxe": "XXE",
    "file-upload": "File Upload",
    "info-disclosure": "Info Disclosure",
    "cors": "CORS",
    "oauth": "OAuth/OIDC/SAML",
    "business-logic": "Business Logic",
    "prototype-pollution": "Prototype Pollution",
    "deserialization": "Deserialization",
    "lfi": "LFI/Traversal",
}

DEFAULT_CLASS_PRIORS = {
    "idor": 15.0,
    "auth-bypass": 13.0,
    "ssrf": 12.0,
    "sqli": 11.0,
    "xss": 10.0,
    "graphql": 9.0,
    "race-condition": 8.0,
    "business-logic": 8.0,
    "file-upload": 7.0,
    "oauth": 7.0,
}

PATH_SIGNAL_MAP: list[tuple[re.Pattern[str], list[str], str]] = [
    (
        re.compile(r"/(billing|wallet|payment|invoice|refund|credit|coupon)"),
        ["race-condition", "business-logic", "idor"],
        "financial workflow signal",
    ),
    (
        re.compile(r"/(oauth|oidc|saml|auth|login|token|callback)"),
        ["auth-bypass", "oauth", "open-redirect"],
        "authentication flow signal",
    ),
    (
        re.compile(r"/(upload|avatar|attachment|import|document|file)"),
        ["file-upload", "ssrf", "xss"],
        "file handling signal",
    ),
    (
        re.compile(r"/(admin|role|permission|tenant|user|account|org)"),
        ["idor", "auth-bypass", "business-logic"],
        "privilege boundary signal",
    ),
    (
        re.compile(r"/(graphql|graphiql)"),
        ["graphql", "idor", "auth-bypass"],
        "GraphQL exposure signal",
    ),
]

STATIC_SURFACE_RE = re.compile(
    r"\.(?:js|css|png|jpg|jpeg|svg|gif|ico|woff2?|ttf|eot|map)(?:\?|$)"
)
IDOR_HINT_RE = re.compile(
    r"([?&](?:id|user_id|account_id|order_id|invoice_id|tenant_id)=|/[0-9]{2,}(?:/|$)|/[0-9a-f]{8}-[0-9a-f-]{27,36}(?:/|$))"
)
MARKETING_HINT_RE = re.compile(r"/(blog|careers|press|docs|status|help|changelog)")

RESULT_ALIASES = {
    "confirmed": "confirmed",
    "pass": "confirmed",
    "survives": "confirmed",
    "killed": "killed",
    "kill": "killed",
    "rejected": "killed",
    "downgraded": "downgraded",
    "downgrade": "downgraded",
    "partial": "partial",
    "potential": "partial",
}

TERMINAL_IMPACTS = {
    "ato",
    "rce",
    "admin",
    "data-exfiltration",
    "cloud-compromise",
}

CAPABILITY_TO_NEXT = {
    "js-execution": [
        ("postmessage-injection", "state-manipulation"),
        ("csrf-token-theft", "authenticated-actions"),
        ("cookie-theft", "session-token"),
    ],
    "text-injection": [
        ("stored-xss", "js-execution"),
        ("template-injection", "server-code-execution"),
    ],
    "url-control": [
        ("oauth-open-redirect", "oauth-token"),
        ("open-redirect-chain", "trusted-phishing"),
    ],
    "ssrf": [
        ("cloud-metadata-access", "cloud-compromise"),
        ("localhost-admin-access", "admin"),
        ("internal-service-enum", "internal-reachability"),
    ],
    "idor-read": [
        ("token-harvest", "session-token"),
        ("cross-tenant-data-exfil", "data-exfiltration"),
    ],
    "idor-write": [
        ("role-escalation", "admin"),
        ("account-state-manipulation", "authenticated-actions"),
    ],
    "file-write": [
        ("web-shell", "rce"),
        ("stored-svg-xss", "js-execution"),
    ],
    "session-token": [
        ("session-hijack", "ato"),
    ],
    "oauth-token": [
        ("oauth-account-takeover", "ato"),
    ],
    "authenticated-actions": [
        ("privilege-escalation-path", "admin"),
    ],
}


def _slugify_target(target: str) -> str:
    return target.replace("://", "-").replace("/", "-").replace(".", "-").replace(":", "-").strip("-")


def _canonicalize_vuln_label(label: str) -> str | None:
    text = label.strip().lower()
    if not text:
        return None
    # Brain exhaustion markers use hyphen/underscore forms (`prototype-pollution`,
    # `race_condition`); fold them into the spaced form that the substring checks
    # below expect so exhaustion penalties actually fire for those classes.
    text = text.replace("-", " ").replace("_", " ")
    if "idor" in text or "bola" in text or "object level" in text or "mass assignment" in text:
        return "idor"
    if "xss" in text or "cross site" in text:
        return "xss"
    if "ssrf" in text or "server-side request forgery" in text:
        return "ssrf"
    if "sqli" in text or "sql injection" in text or "nosql" in text:
        return "sqli"
    if "csrf" in text:
        return "csrf"
    if "rce" in text or "command injection" in text or "spel" in text:
        return "rce"
    if "ssti" in text or "template injection" in text:
        return "ssti"
    if "auth bypass" in text or "account takeover" in text or "password reset" in text:
        return "auth-bypass"
    if "open redirect" in text:
        return "open-redirect"
    if "graphql" in text:
        return "graphql"
    if "race condition" in text or "toctou" in text:
        return "race-condition"
    if "xxe" in text:
        return "xxe"
    if "upload" in text:
        return "file-upload"
    if "info disclosure" in text or "data leak" in text or "sensitive data" in text:
        return "info-disclosure"
    if "cors" in text:
        return "cors"
    if "oauth" in text or "oidc" in text or "saml" in text:
        return "oauth"
    if "business logic" in text or "workflow" in text:
        return "business-logic"
    if "prototype pollution" in text:
        return "prototype-pollution"
    if "deserial" in text:
        return "deserialization"
    if "lfi" in text or "path traversal" in text or "directory traversal" in text:
        return "lfi"
    return None


def _display_name(vuln_class: str) -> str:
    return DISPLAY_NAMES.get(vuln_class, vuln_class)


def _normalize_result(result: str) -> str:
    value = result.strip().lower()
    return RESULT_ALIASES.get(value, value)


def _load_intel(path: Path | None = None) -> dict:
    """Load intel.json or quarantine a corrupt copy (never silently discard)."""
    intel_path = path or Path("intel.json")
    return load_json_or_quarantine(intel_path, dict)


def _extract_exhausted_classes(target: str, brain_dir: Path | None = None) -> set[str]:
    """Read exhausted classes from brain files for a target."""
    if not target:
        return set()
    root = brain_dir or Path(".claude/agent-memory-local/brain")
    exhausted: set[str] = set()

    exhausted_file = root / "techniques" / "exhausted.md"
    if exhausted_file.exists():
        for line in exhausted_file.read_text().splitlines():
            if not line.startswith("[") or target.lower() not in line.lower():
                continue
            for cls in CANONICAL_VULN_CLASSES:
                if cls in line.lower() or _display_name(cls).lower() in line.lower():
                    exhausted.add(cls)

    target_file = root / "targets" / f"{_slugify_target(target)}.md"
    if target_file.exists():
        content = target_file.read_text().lower()
        for match in re.findall(r"coverage-([a-z0-9_-]+)", content):
            canon = _canonicalize_vuln_label(match)
            if canon:
                exhausted.add(canon)

    return exhausted


def _default_telemetry_state() -> dict:
    return {
        "version": 1,
        "by_class": {},
        "totals": {"attempts": 0, "confirmed": 0, "killed": 0, "downgraded": 0, "partial": 0},
    }


def load_telemetry(path: Path | None = None) -> dict:
    """Load autonomy telemetry or quarantine a corrupt copy.

    A corrupt file is moved aside to ``<path>.corrupt-<epoch>`` — it is never
    silently overwritten, which would erase every historical outcome the
    telemetry adjustment uses to reprioritise classes.
    """
    state_path = path or Path(".autonomy-telemetry.json")
    data = load_json_or_quarantine(state_path, _default_telemetry_state)
    if not isinstance(data, dict):
        # Valid JSON but wrong shape (e.g. a list). Treat identically to corrupt
        # — preserve and start fresh rather than crash downstream callers.
        print(
            f"WARNING: telemetry file {state_path} had unexpected shape "
            f"({type(data).__name__}); starting fresh.",
            file=sys.stderr,
        )
        return _default_telemetry_state()
    return data


def save_telemetry(state: dict, path: Path | None = None) -> None:
    """Persist telemetry atomically (temp + os.replace) to survive crashes."""
    state_path = path or Path(".autonomy-telemetry.json")
    atomic_write_text(state_path, json.dumps(state, indent=2))


def record_hunt_outcome(
    vuln_class: str,
    result: str,
    attempts: int = 0,
    elapsed_minutes: float = 0.0,
    telemetry: dict | None = None,
) -> dict:
    """Update autonomy telemetry with one hunt outcome.

    Raises ``ValueError`` for an unknown ``result`` (CLI already restricts
    choices, but direct library callers must not silently skip the bucket
    update — that would inflate ``events`` without crediting any outcome
    and ``telemetry_adjustment`` would penalise the class falsely).
    """
    telemetry = telemetry or _default_telemetry_state()
    klass = _canonicalize_vuln_label(vuln_class)
    if klass is None:
        # Store under a normalised-lowercase key but flag the caller so SSRF/ssrf
        # don't become two separate rows over time.
        klass = vuln_class.strip().lower()
        print(
            f"WARNING: vuln_class '{vuln_class}' not in canonical set; "
            f"storing under '{klass}'. Add it to _canonicalize_vuln_label "
            "if it's a real class.",
            file=sys.stderr,
        )
    norm = _normalize_result(result)
    if norm not in {"confirmed", "killed", "downgraded", "partial"}:
        raise ValueError(
            f"Unknown hunt outcome '{result}'. "
            f"Must be one of: confirmed, killed, downgraded, partial "
            f"(aliases: pass/survives → confirmed, kill/rejected → killed, "
            f"downgrade → downgraded, potential → partial)."
        )
    cls = telemetry.setdefault("by_class", {}).setdefault(
        klass,
        {
            "attempts": 0,
            "confirmed": 0,
            "killed": 0,
            "downgraded": 0,
            "partial": 0,
            "elapsed_minutes": 0.0,
            "events": 0,
        },
    )
    cls["events"] += 1
    cls["attempts"] += max(0, int(attempts))
    cls["elapsed_minutes"] += max(0.0, float(elapsed_minutes))
    cls[norm] += 1
    telemetry["totals"][norm] = telemetry["totals"].get(norm, 0) + 1
    telemetry["totals"]["attempts"] = telemetry["totals"].get("attempts", 0) + max(0, int(attempts))
    return telemetry


def telemetry_adjustment(vuln_class: str, telemetry: dict | None = None) -> tuple[float, list[str]]:
    """Compute score delta from historical autonomous outcomes."""
    telemetry = telemetry or _default_telemetry_state()
    cls = telemetry.get("by_class", {}).get(vuln_class, {})
    events = int(cls.get("events", 0))
    if events <= 0:
        return 0.0, []
    confirmed = int(cls.get("confirmed", 0))
    killed = int(cls.get("killed", 0))
    downgraded = int(cls.get("downgraded", 0))
    partial = int(cls.get("partial", 0))
    attempts = int(cls.get("attempts", 0))

    success_rate = confirmed / max(1, events)
    kill_rate = killed / max(1, events)
    partial_rate = partial / max(1, events)
    downgrade_rate = downgraded / max(1, events)

    delta = 0.0
    delta += min(20.0, success_rate * 24.0)
    delta += min(6.0, partial_rate * 8.0)
    delta -= min(16.0, kill_rate * 18.0)
    delta -= min(8.0, downgrade_rate * 10.0)

    avg_attempts = attempts / max(1, events)
    if avg_attempts > 0:
        if avg_attempts < 20:
            delta += 3.0
        elif avg_attempts > 80:
            delta -= 4.0

    reasons = [
        f"telemetry success_rate={success_rate:.2f} kill_rate={kill_rate:.2f} (+{delta:.1f})"
    ]
    return delta, reasons


def recommend_vuln_classes(
    tech_stack: str,
    intel: dict | None = None,
    exhausted: set[str] | None = None,
    telemetry: dict | None = None,
    limit: int = 8,
) -> list[dict]:
    """Rank vuln classes for autonomous hunt dispatch order."""
    intel = intel or {}
    exhausted = exhausted or set()

    scores: dict[str, float] = defaultdict(float)
    reasons: dict[str, list[str]] = defaultdict(list)
    for cls, base in DEFAULT_CLASS_PRIORS.items():
        scores[cls] += base
        reasons[cls].append(f"base prior +{base:.1f}")

    stack = tech_stack.lower()
    for tech, vulns in TECH_VULN_MAP.items():
        if tech not in stack:
            continue
        for raw in vulns:
            canon = _canonicalize_vuln_label(raw)
            if not canon:
                continue
            scores[canon] += 22.0
            reasons[canon].append(f"tech signal {tech} (+22)")

    for raw, count in (intel.get("by_vuln_type") or {}).items():
        canon = _canonicalize_vuln_label(raw)
        if not canon:
            continue
        boost = min(24.0, float(count) * 3.0)
        scores[canon] += boost
        reasons[canon].append(f"hacktivity frequency {raw} x{count} (+{boost:.1f})")

    for row in (intel.get("vuln_roi") or []):
        canon = _canonicalize_vuln_label(str(row.get("vuln", "")))
        if not canon:
            continue
        avg = float(row.get("avg", 0) or 0)
        paid = int(row.get("count_paid", 0) or 0)
        boost = min(30.0, (avg / 1500.0) + (paid * 2.0))
        scores[canon] += boost
        reasons[canon].append(f"ROI avg ${int(avg):,}, paid {paid} (+{boost:.1f})")

    for path, raw_count in (intel.get("top_paths") or {}).items():
        count = int(raw_count or 0)
        if count <= 0:
            continue
        path_l = str(path).lower()
        for pattern, classes, signal in PATH_SIGNAL_MAP:
            if not pattern.search(path_l):
                continue
            boost = min(10.0, 2.0 + count * 1.5)
            for cls in classes:
                scores[cls] += boost
                reasons[cls].append(f"{signal}: {path} (+{boost:.1f})")

    for cls in exhausted:
        if cls not in CANONICAL_VULN_CLASSES:
            continue
        scores[cls] -= 35.0
        reasons[cls].append("brain exhausted penalty (-35)")

    telemetry = telemetry or _default_telemetry_state()
    for cls in CANONICAL_VULN_CLASSES:
        delta, signal = telemetry_adjustment(cls, telemetry)
        if not delta:
            continue
        scores[cls] += delta
        reasons[cls].extend(signal)

    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    out: list[dict] = []
    for cls, score in ranked:
        if score <= 0:
            continue
        out.append(
            {
                "vuln_class": cls,
                "display": _display_name(cls),
                "score": round(score, 2),
                "exhausted": cls in exhausted,
                "reasons": reasons[cls][:5],
            }
        )
        if len(out) >= limit:
            break
    return out


def show_recommended_classes(
    tech_stack: str,
    target: str = "",
    limit: int = 8,
    intel_path: Path | None = None,
    brain_dir: Path | None = None,
    output: Path | None = None,
    telemetry_path: Path | None = None,
) -> int:
    intel = _load_intel(intel_path)
    telemetry = load_telemetry(telemetry_path)
    exhausted = _extract_exhausted_classes(target, brain_dir) if target else set()
    ranked = recommend_vuln_classes(
        tech_stack=tech_stack,
        intel=intel,
        exhausted=exhausted,
        telemetry=telemetry,
        limit=limit,
    )
    if not ranked:
        print("No class hypotheses could be generated.")
        return 1

    # Signal data confidence to the operator. If we had no tech signal AND
    # no hacktivity AND no brain signal, the ranking is effectively priors —
    # don't let downstream treat that as "evidence-backed".
    has_tech = bool(tech_stack and tech_stack.strip())
    has_intel = bool(intel.get("vuln_roi"))
    has_brain = bool(exhausted)
    confidence = "high" if (has_tech and has_intel) else ("medium" if (has_tech or has_intel or has_brain) else "low")

    print("🧠 Autonomous class hypotheses")
    if target:
        print(f"   Target: {target}")
    print(f"   Tech stack: {tech_stack or '(unknown)'}")
    print(f"   Data confidence: {confidence} (tech={has_tech}, hacktivity={has_intel}, brain={has_brain})")
    if confidence == "low":
        print("   ⚠ Falling back to default priors — scores are weakly grounded.")
    print("")
    for i, row in enumerate(ranked, start=1):
        exhausted_tag = " [EXHAUSTED]" if row["exhausted"] else ""
        print(f"{i:02d}. {row['display']} — score {row['score']:.1f}{exhausted_tag}")
        for reason in row["reasons"][:3]:
            print(f"    - {reason}")

    if output:
        lines = [
            "# Autonomous Vulnerability Class Hypotheses",
            "",
            f"- Target: {target or '(not provided)'}",
            f"- Tech stack: {tech_stack or '(unknown)'}",
            "",
            "## Ranked Classes",
            "",
        ]
        for i, row in enumerate(ranked, start=1):
            exhausted_tag = " (exhausted penalty applied)" if row["exhausted"] else ""
            lines.append(f"{i}. **{row['display']}** — `{row['score']:.1f}`{exhausted_tag}")
            for reason in row["reasons"]:
                lines.append(f"   - {reason}")
        output.write_text("\n".join(lines) + "\n")
    return 0


def allocate_class_budget(
    class_scores: list[dict],
    total_minutes: int = 120,
    total_tokens: int = 30000,
    min_minutes: int = 8,
    min_tokens: int = 800,
) -> list[dict]:
    """Allocate autonomous hunt budget by normalized class score.

    Classes with score ≤ 0 (typically exhausted or disqualified by the
    exhaustion penalty) are dropped before allocation — otherwise the
    ``max(0.1, ...)`` floor lets them consume ``min_minutes`` * N of the
    budget that should go to viable classes. If every class scores ≤ 0
    there's nothing worth hunting; return empty.
    """
    if not class_scores:
        return []
    viable = [row for row in class_scores if float(row.get("score", 0.0)) > 0.0]
    if not viable:
        return []
    positives = [float(row.get("score", 0.0)) for row in viable]
    total = sum(positives)
    budgets: list[dict] = []
    for row, weight in zip(viable, positives):
        ratio = weight / total
        minutes = max(min_minutes, int(total_minutes * ratio))
        tokens = max(min_tokens, int(total_tokens * ratio))
        budgets.append(
            {
                "vuln_class": row["vuln_class"],
                "display": row.get("display", row["vuln_class"]),
                "score": float(row.get("score", 0.0)),
                "weight": round(ratio, 4),
                "budget_minutes": minutes,
                "budget_tokens": tokens,
            }
        )
    return budgets


def show_class_budget(
    tech_stack: str,
    target: str = "",
    total_minutes: int = 120,
    total_tokens: int = 30000,
    limit: int = 8,
    intel_path: Path | None = None,
    brain_dir: Path | None = None,
    telemetry_path: Path | None = None,
    output: Path | None = None,
) -> int:
    intel = _load_intel(intel_path)
    telemetry = load_telemetry(telemetry_path)
    exhausted = _extract_exhausted_classes(target, brain_dir) if target else set()
    ranked = recommend_vuln_classes(
        tech_stack=tech_stack,
        intel=intel,
        exhausted=exhausted,
        telemetry=telemetry,
        limit=limit,
    )
    if not ranked:
        print("No ranked classes available for budget allocation.")
        return 1
    budgets = allocate_class_budget(
        ranked, total_minutes=total_minutes, total_tokens=total_tokens
    )
    print("⏱️ Autonomous budget allocation")
    print(f"   Total minutes={total_minutes}, total tokens={total_tokens}")
    for row in budgets:
        print(
            f"- {row['display']} [{row['score']:.1f}] → "
            f"{row['budget_minutes']}m, {row['budget_tokens']} tokens (w={row['weight']:.3f})"
        )
    if output:
        lines = [
            "# Autonomous Class Budget",
            "",
            f"- Target: {target or '(not provided)'}",
            f"- Tech stack: {tech_stack or '(unknown)'}",
            f"- Total minutes: {total_minutes}",
            f"- Total tokens: {total_tokens}",
            "",
        ]
        for row in budgets:
            lines.append(
                f"- **{row['display']}** (`{row['score']:.1f}`): "
                f"{row['budget_minutes']}m / {row['budget_tokens']} tokens"
            )
        output.write_text("\n".join(lines) + "\n")
    return 0


def evaluate_exhaustion_gate(
    *,
    attempts: int,
    combos_tested: int,
    combos_remaining: int,
    encoding_steps: int,
    differential_evidence: bool,
    hard_blocker: str = "",
) -> tuple[bool, str]:
    """Decide whether class exhaustion criteria are met."""
    if hard_blocker.strip():
        return True, f"hard blocker accepted: {hard_blocker.strip()}"
    if attempts < 25:
        return False, "attempt floor unmet (<25)"
    if combos_tested < 8:
        return False, "combination floor unmet (<8)"
    if encoding_steps < 3:
        return False, "encoding ladder depth too shallow (<3)"
    if not differential_evidence:
        return False, "missing differential evidence"
    if combos_remaining > max(5, combos_tested // 2):
        return False, "too much matrix unexplored"
    return True, "exhaustion gate passed"


def _normalize_capability(value: str) -> str:
    text = value.strip().lower()
    if not text:
        return text
    if "js" in text and "execution" in text:
        return "js-execution"
    if "text injection" in text:
        return "text-injection"
    if "url" in text and ("control" in text or "redirect" in text):
        return "url-control"
    if "ssrf" in text:
        return "ssrf"
    if "idor" in text and "write" in text:
        return "idor-write"
    if "idor" in text:
        return "idor-read"
    if "file" in text and ("write" in text or "upload" in text):
        return "file-write"
    if "session" in text and "token" in text:
        return "session-token"
    if "oauth" in text and "token" in text:
        return "oauth-token"
    if "auth" in text and "action" in text:
        return "authenticated-actions"
    return text.replace(" ", "-")


def suggest_chain_steps(
    capabilities: list[str],
    known: set[str] | None = None,
    limit: int = 6,
) -> list[dict]:
    """Suggest next chain links from observed attacker capabilities."""
    known = known or set()
    suggestions: list[dict] = []
    for raw in capabilities:
        cap = _normalize_capability(raw)
        for next_bug, gained in CAPABILITY_TO_NEXT.get(cap, []):
            if next_bug in known:
                continue
            terminal = gained in TERMINAL_IMPACTS
            priority = 100 if terminal else 60
            suggestions.append(
                {
                    "from_capability": cap,
                    "next_bug": next_bug,
                    "gained_capability": gained,
                    "terminal_impact": terminal,
                    "priority": priority,
                }
            )
    suggestions.sort(key=lambda row: (row["priority"], row["next_bug"]), reverse=True)
    return suggestions[:limit]


def show_chain_plan(
    capabilities_file: Path,
    output: Path | None = None,
    limit: int = 8,
) -> int:
    if not capabilities_file.exists():
        print(f"Capability graph file not found: {capabilities_file}")
        return 1
    try:
        graph = json.loads(capabilities_file.read_text())
    except json.JSONDecodeError:
        print(f"Invalid JSON in capability graph: {capabilities_file}")
        return 1
    if not isinstance(graph, dict):
        print(f"Unexpected capability graph shape (expected object): {capabilities_file}")
        return 2
    nodes = graph.get("nodes")
    if nodes is None:
        nodes = {}
    if not isinstance(nodes, dict):
        print(f"Capability graph 'nodes' must be an object, got {type(nodes).__name__}: {capabilities_file}")
        return 2
    edges = graph.get("edges")
    if edges is None:
        edges = []
    if not isinstance(edges, list):
        print(f"Capability graph 'edges' must be a list, got {type(edges).__name__}: {capabilities_file}")
        return 2
    capabilities = [
        (node.get("label", key) if isinstance(node, dict) else key)
        for key, node in nodes.items()
    ]
    known = {edge.get("to", "") for edge in edges if isinstance(edge, dict)}
    suggestions = suggest_chain_steps(capabilities=capabilities, known=known, limit=limit)
    if not suggestions:
        print("No chain extensions suggested from current capability graph.")
        return 1
    print("🔗 Autonomous chain planner")
    for row in suggestions:
        terminal = " [TERMINAL]" if row["terminal_impact"] else ""
        print(
            f"- from {row['from_capability']} → test {row['next_bug']} "
            f"→ gain {row['gained_capability']}{terminal}"
        )
    if output:
        lines = ["# Autonomous Chain Plan", ""]
        for row in suggestions:
            terminal = " (terminal)" if row["terminal_impact"] else ""
            lines.append(
                f"- `{row['from_capability']}` → **{row['next_bug']}** "
                f"→ `{row['gained_capability']}`{terminal}"
            )
        output.write_text("\n".join(lines) + "\n")
    return 0


def evidence_sufficiency_score(
    *,
    has_http_pair: bool,
    has_readback: bool,
    has_browser_verification: bool,
    reliability_runs: int,
    reliability_hits: int,
    has_harm_artifact: bool,
    chain_depth: int = 1,
) -> dict:
    """Score finding evidence quality for autonomous pre-report gating."""
    score = 0
    notes: list[str] = []
    if has_http_pair:
        score += 25
    else:
        notes.append("missing exploit request/response pair")
    if has_readback:
        score += 20
    else:
        notes.append("missing independent read-back")
    if has_browser_verification:
        score += 15
    if has_harm_artifact:
        score += 20
    else:
        notes.append("missing concrete harm artifact")
    if reliability_runs > 0:
        hit_rate = reliability_hits / max(1, reliability_runs)
        score += int(min(20.0, hit_rate * 20.0))
        if hit_rate < 0.8:
            notes.append(f"low reliability ({hit_rate:.2f})")
    if chain_depth >= 2:
        score += min(10, chain_depth * 2)

    decision = "PASS"
    if score < 55:
        decision = "KILL"
    elif score < 75:
        decision = "DOWNGRADE"
    return {"score": score, "decision": decision, "notes": notes}


def score_surface_endpoint(endpoint: str, tech_stack: str = "") -> dict[str, object]:
    """Score one endpoint for exploitability-first autonomous ranking."""
    lower = endpoint.strip().lower()
    score = 0.0
    reasons: list[str] = []

    if IDOR_HINT_RE.search(lower):
        score += 22.0
        reasons.append("object-id signal (+22)")
    if "/graphql" in lower or "graphiql" in lower or lower.startswith("ws://") or lower.startswith("wss://"):
        score += 18.0
        reasons.append("GraphQL/WebSocket signal (+18)")
    if "/api/" in lower or lower.startswith("api.") or "/v1/" in lower or "/v2/" in lower:
        score += 14.0
        reasons.append("dynamic API surface (+14)")
    if re.search(r"/(billing|wallet|payment|invoice|refund|credit|coupon)", lower):
        score += 20.0
        reasons.append("financial workflow (+20)")
    if re.search(r"/(upload|import|webhook|callback|document|file)", lower):
        score += 14.0
        reasons.append("ingest/file interface (+14)")
    if re.search(r"/(admin|role|permission|tenant|manage)", lower):
        score += 10.0
        reasons.append("privilege boundary route (+10)")
    if re.search(r":(8080|8443|3000|5000|5601|9200)(?:/|$)", lower):
        score += 10.0
        reasons.append("non-standard port (+10)")

    if STATIC_SURFACE_RE.search(lower):
        score -= 25.0
        reasons.append("static asset surface (-25)")
    if MARKETING_HINT_RE.search(lower):
        score -= 18.0
        reasons.append("marketing/documentation surface (-18)")
    if "cdn." in lower or "jsdelivr.net" in lower or "googleapis.com" in lower:
        score -= 20.0
        reasons.append("likely third-party/CDN (-20)")

    stack = tech_stack.lower()
    if "graphql" in stack and "/graphql" in lower:
        score += 6.0
        reasons.append("stack match boost (+6)")
    if ("rails" in stack or "django" in stack or "laravel" in stack) and IDOR_HINT_RE.search(lower):
        score += 5.0
        reasons.append("framework→IDOR boost (+5)")

    bucket = "Kill"
    if score >= 35:
        bucket = "P1"
    elif score >= 15:
        bucket = "P2"

    return {
        "endpoint": endpoint.strip(),
        "score": round(score, 2),
        "bucket": bucket,
        "reasons": reasons,
    }


def rank_surface(endpoints: list[str], tech_stack: str = "", limit: int = 100) -> list[dict[str, object]]:
    seen: set[str] = set()
    scored: list[dict[str, object]] = []
    for raw in endpoints:
        ep = raw.strip()
        if not ep or ep in seen:
            continue
        seen.add(ep)
        scored.append(score_surface_endpoint(ep, tech_stack=tech_stack))
    scored.sort(key=lambda row: (float(row["score"]), row["endpoint"]), reverse=True)
    return scored[:limit]


def _load_endpoints_file(path: Path) -> list[str]:
    endpoints: list[str] = []
    for line in path.read_text().splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        endpoints.append(value.split()[0])
    return endpoints


def show_ranked_surface(
    endpoints_file: Path,
    tech_stack: str = "",
    limit: int = 60,
    output: Path | None = None,
) -> int:
    if not endpoints_file.exists():
        print(f"Endpoints file not found: {endpoints_file}")
        return 1
    ranked = rank_surface(_load_endpoints_file(endpoints_file), tech_stack=tech_stack, limit=limit)
    if not ranked:
        print("No endpoints to rank.")
        return 1

    p1 = [r for r in ranked if r["bucket"] == "P1"]
    p2 = [r for r in ranked if r["bucket"] == "P2"]
    kill = [r for r in ranked if r["bucket"] == "Kill"]
    print("🎯 Autonomous surface ranking")
    print(f"   Inputs: {len(ranked)} endpoints (from {endpoints_file})")
    print(f"   Split: P1={len(p1)} P2={len(p2)} Kill={len(kill)}")
    print("")
    for bucket, rows in [("P1", p1), ("P2", p2), ("Kill", kill)]:
        print(f"{bucket}:")
        for row in rows[:20]:
            print(f"  - {row['endpoint']}  [{row['score']:.1f}]")
            if row["reasons"]:
                print(f"    {row['reasons'][0]}")
        print("")

    if output:
        lines = [
            "# Attack Surface Ranking (Autonomous)",
            "",
            f"- Source file: `{endpoints_file}`",
            f"- Tech stack hint: `{tech_stack or 'unknown'}`",
            "",
            f"- P1: {len(p1)}",
            f"- P2: {len(p2)}",
            f"- Kill: {len(kill)}",
            "",
        ]
        for bucket, rows in [("P1", p1), ("P2", p2), ("Kill", kill)]:
            lines.extend([f"## {bucket}", ""])
            for row in rows:
                lines.append(f"- `{row['endpoint']}` — score `{row['score']:.1f}`")
                for reason in row["reasons"][:3]:
                    lines.append(f"  - {reason}")
            lines.append("")
        output.write_text("\n".join(lines))
    return 0


def _default_attack_matrix() -> dict[str, dict[str, list[str]]]:
    """Per-class 3D matrix: vector × encoding × bypass family.

    Designed to feed hunter agents a structured "don't stop after one payload"
    checklist. Keys match the vuln-class canonical names used elsewhere.

    Encoding entries include SINGLE encodings (url, html-entity, unicode-escape)
    AND STACKED encodings within one payload (url+html-entity, double-url,
    unicode+url, base64+url). Stacked encodings defeat WAFs that decode once
    but let the target decode twice — a common and rewarding bypass class.
    """
    return {
        "xss": {
            "vectors": ["query", "path", "hash", "post-body", "json", "multipart", "websocket"],
            "encodings": [
                # single
                "raw", "url", "html-entity", "unicode-escape", "mixed-case",
                # stacked in one payload
                "double-url", "html-entity+url", "url+html-entity",
                "unicode-escape+url", "html-entity+mixed-case",
            ],
            "bypasses": ["tag-breakout", "event-handler", "svg-polyglot", "template-injection"],
        },
        "sqli": {
            "vectors": ["query", "json", "graphql", "cookie", "header"],
            "encodings": [
                "raw", "url", "utf16", "comment-obfuscation",
                "double-url", "url+comment", "hex-literal+url",
            ],
            "bypasses": ["boolean-based", "time-based", "stacked", "waf-keyword-split"],
        },
        "ssrf": {
            "vectors": ["url-param", "webhook", "importer", "pdf-renderer", "image-fetcher"],
            "encodings": [
                "raw", "url", "ipv6", "decimal-ip", "octal-ip", "mixed-scheme",
                "double-url", "url+decimal-ip", "url+octal-ip", "idn-then-url",
            ],
            "bypasses": [
                "dns-rebinding", "open-redirect-hop", "gopher", "host-header-confusion",
            ],
        },
        "idor": {
            "vectors": ["rest-id", "graphql-node", "bulk-export", "search-filter", "file-download"],
            "encodings": [
                "numeric", "uuid", "base64", "url",
                "double-url", "base64+url", "url+hex",
            ],
            "bypasses": ["method-swap", "tenant-switch", "batch-abuse", "sibling-resource", "state-race"],
        },
        "ssti": {
            "vectors": ["email-template", "report-render", "admin-message", "webhook-body", "pdf-template"],
            "encodings": ["raw", "url", "unicode-escape", "hex-attr", "concat-runtime"],
            "bypasses": [
                "attr-filter-bypass", "pipe-format", "class-mro-walk", "builtins-lookup", "object-type-pivot",
            ],
        },
        "rce": {
            "vectors": ["command-param", "eval-sink", "template-render", "file-upload-exec", "deserialize"],
            "encodings": ["raw", "url", "base64", "shell-quote", "env-substitution"],
            "bypasses": ["space-alt", "cmd-concat", "here-string", "ifs-abuse", "quoted-bypass"],
        },
        "oauth": {
            "vectors": ["authorize", "token", "callback", "userinfo", "introspect"],
            "encodings": ["raw", "url", "base64"],
            "bypasses": [
                "redirect-uri-mismatch", "state-fixation", "pkce-bypass", "mix-up", "subdomain-confusion",
            ],
        },
        "graphql": {
            "vectors": ["query", "mutation", "subscription", "batched", "persisted-query"],
            "encodings": ["raw", "aliased", "fragment-spread", "inline-fragment"],
            "bypasses": ["introspection-auth", "node-idor", "batch-dos", "directive-override", "field-suggestion"],
        },
        "upload": {
            "vectors": ["multipart", "base64-json", "presigned-url", "chunked", "graphql-upload"],
            "encodings": ["raw", "magic-byte", "double-extension", "null-byte", "polyglot"],
            "bypasses": ["content-type-spoof", "case-ext", "path-traversal-name", "mime-sniff", "zip-slip"],
        },
    }


def build_attack_matrix(
    vuln_class: str,
    limit: int = 250,
    profile: dict[str, dict[str, list[str]]] | None = None,
) -> list[dict[str, str]]:
    matrix = profile or _default_attack_matrix()
    key = vuln_class.strip().lower()
    if key not in matrix:
        return []
    cfg = matrix[key]
    combos: list[dict[str, str]] = []
    for vector in cfg["vectors"]:
        for encoding in cfg["encodings"]:
            for bypass in cfg["bypasses"]:
                combos.append(
                    {
                        "vuln_class": key,
                        "vector": vector,
                        "encoding": encoding,
                        "bypass": bypass,
                        "label": f"{key}:{vector}:{encoding}:{bypass}",
                    }
                )
                if len(combos) >= limit:
                    return combos
    return combos


def suggest_for_tech(tech_stack: str) -> None:
    """Suggest vuln classes based on tech stack."""
    tech_lower = tech_stack.lower()
    seen: set[tuple[str, str]] = set()
    suggestions: list[tuple[str, str]] = []
    for tech, vulns in TECH_VULN_MAP.items():
        if tech in tech_lower:
            for v in vulns:
                key = (tech, v)
                if key not in seen:
                    seen.add(key)
                    suggestions.append(key)

    if suggestions:
        print(f"🎯 Suggested vuln classes for '{tech_stack}':")
        for tech, vuln in suggestions:
            print(f"   [{tech}] → {vuln}")
    else:
        print(
            f"No specific suggestions for '{tech_stack}'. "
            "Try: rails, django, express, next.js, graphql, php, spring"
        )


def show_matrix(vuln_class: str, limit: int) -> int:
    combos = build_attack_matrix(vuln_class=vuln_class, limit=limit)
    if not combos:
        profiles = sorted(_default_attack_matrix())
        print(
            f"No matrix profile for '{vuln_class}'. "
            f"Available: {', '.join(profiles)}."
        )
        return 1
    print(f"🧪 {vuln_class.upper()} deep hunt matrix ({len(combos)} combinations)")
    for i, combo in enumerate(combos, start=1):
        print(
            f"{i:03d}. vector={combo['vector']} "
            f"encoding={combo['encoding']} bypass={combo['bypass']}"
        )
    return 0


def show_patterns() -> None:
    """Show accumulated intel patterns."""
    intel_path = Path("intel.json")
    if not intel_path.exists():
        print("No intel data. Run: python3 tools/intel_engine.py analyze")
        return
    print(json.dumps(json.loads(intel_path.read_text()), indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="Hacktivity intelligence engine")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("analyze", help="Analyze hacktivity.md")
    sub.add_parser("patterns", help="Show learned patterns")
    suggest_p = sub.add_parser("suggest", help="Suggest vulns for tech stack")
    suggest_p.add_argument("tech_stack")
    matrix_p = sub.add_parser(
        "matrix",
        help="Generate deep vector/encoding/bypass combinations for a vuln class",
    )
    matrix_p.add_argument("vuln_class")
    matrix_p.add_argument("--limit", type=int, default=250)
    classes_p = sub.add_parser(
        "classes",
        help="Rank vuln classes autonomously from tech stack + intel + brain exhaustion",
    )
    classes_p.add_argument("--tech-stack", default="", help="Tech stack fingerprint string")
    classes_p.add_argument("--target", default="", help="Target name to load brain exhaustion hints")
    classes_p.add_argument("--limit", type=int, default=8)
    classes_p.add_argument("--intel-path", default="intel.json")
    classes_p.add_argument("--brain-dir", default=".claude/agent-memory-local/brain")
    classes_p.add_argument(
        "--output",
        default=None,
        help="Write markdown ranking to this path. Default: stdout only.",
    )
    classes_p.add_argument("--telemetry-path", default=".autonomy-telemetry.json")
    rank_p = sub.add_parser(
        "rank-surface",
        help="Rank endpoints into P1/P2/Kill using exploitability-first scoring",
    )
    rank_p.add_argument("--endpoints-file", required=True, help="Path to newline-delimited endpoints")
    rank_p.add_argument("--tech-stack", default="", help="Tech stack hint")
    rank_p.add_argument("--limit", type=int, default=60)
    rank_p.add_argument(
        "--output",
        default=None,
        help="Write markdown ranking to this path. Default: stdout only.",
    )
    budget_p = sub.add_parser(
        "budget",
        help="Allocate autonomous class budgets from ranked hypotheses",
    )
    budget_p.add_argument("--tech-stack", default="")
    budget_p.add_argument("--target", default="")
    budget_p.add_argument("--total-minutes", type=int, default=120)
    budget_p.add_argument("--total-tokens", type=int, default=30000)
    budget_p.add_argument("--limit", type=int, default=8)
    budget_p.add_argument("--intel-path", default="intel.json")
    budget_p.add_argument("--brain-dir", default=".claude/agent-memory-local/brain")
    budget_p.add_argument("--telemetry-path", default=".autonomy-telemetry.json")
    budget_p.add_argument(
        "--output",
        default=None,
        help="Write markdown budget to this path. Default: stdout only.",
    )
    exhaustion_p = sub.add_parser(
        "exhaustion-gate",
        help="Evaluate whether exhaustion quality bar is met",
    )
    exhaustion_p.add_argument("--attempts", type=int, required=True)
    exhaustion_p.add_argument("--combos-tested", type=int, required=True)
    exhaustion_p.add_argument("--combos-remaining", type=int, required=True)
    exhaustion_p.add_argument("--encoding-steps", type=int, required=True)
    exhaustion_p.add_argument("--differential-evidence", action="store_true")
    exhaustion_p.add_argument("--hard-blocker", default="")
    telemetry_p = sub.add_parser(
        "record-outcome",
        help="Record autonomous hunt outcome for telemetry reprioritization",
    )
    telemetry_p.add_argument("--vuln-class", required=True)
    telemetry_p.add_argument(
        "--result",
        required=True,
        choices=["confirmed", "kill", "killed", "downgrade", "downgraded", "partial", "potential"],
    )
    telemetry_p.add_argument("--attempts", type=int, default=0)
    telemetry_p.add_argument("--elapsed-minutes", type=float, default=0.0)
    telemetry_p.add_argument("--telemetry-path", default=".autonomy-telemetry.json")
    chain_p = sub.add_parser(
        "chain-plan",
        help="Suggest next chain links from capability graph",
    )
    chain_p.add_argument(
        "--capability-file",
        default=".claude/agent-memory-local/brain/patterns/capability-graph.json",
    )
    chain_p.add_argument(
        "--output",
        default=None,
        help="Write markdown chain plan to this path. Default: stdout only.",
    )
    chain_p.add_argument("--limit", type=int, default=8)
    evidence_p = sub.add_parser(
        "evidence-score",
        help="Score finding evidence sufficiency for autonomous pre-report gate",
    )
    evidence_p.add_argument("--has-http-pair", action="store_true")
    evidence_p.add_argument("--has-readback", action="store_true")
    evidence_p.add_argument("--has-browser-verification", action="store_true")
    evidence_p.add_argument("--reliability-runs", type=int, default=0)
    evidence_p.add_argument("--reliability-hits", type=int, default=0)
    evidence_p.add_argument("--has-harm-artifact", action="store_true")
    evidence_p.add_argument("--chain-depth", type=int, default=1)

    args = parser.parse_args()
    if args.command == "analyze":
        analyze_hacktivity()
    elif args.command == "patterns":
        show_patterns()
    elif args.command == "suggest":
        suggest_for_tech(args.tech_stack)
    elif args.command == "matrix":
        sys.exit(show_matrix(args.vuln_class, args.limit))
    elif args.command == "classes":
        output = Path(args.output) if args.output else None
        intel_path = Path(args.intel_path) if args.intel_path else None
        brain_dir = Path(args.brain_dir) if args.brain_dir else None
        telemetry_path = Path(args.telemetry_path) if args.telemetry_path else None
        sys.exit(
            show_recommended_classes(
                tech_stack=args.tech_stack,
                target=args.target,
                limit=args.limit,
                intel_path=intel_path,
                brain_dir=brain_dir,
                output=output,
                telemetry_path=telemetry_path,
            )
        )
    elif args.command == "rank-surface":
        output = Path(args.output) if args.output else None
        sys.exit(
            show_ranked_surface(
                endpoints_file=Path(args.endpoints_file),
                tech_stack=args.tech_stack,
                limit=args.limit,
                output=output,
            )
        )
    elif args.command == "budget":
        output = Path(args.output) if args.output else None
        intel_path = Path(args.intel_path) if args.intel_path else None
        brain_dir = Path(args.brain_dir) if args.brain_dir else None
        telemetry_path = Path(args.telemetry_path) if args.telemetry_path else None
        sys.exit(
            show_class_budget(
                tech_stack=args.tech_stack,
                target=args.target,
                total_minutes=args.total_minutes,
                total_tokens=args.total_tokens,
                limit=args.limit,
                intel_path=intel_path,
                brain_dir=brain_dir,
                telemetry_path=telemetry_path,
                output=output,
            )
        )
    elif args.command == "exhaustion-gate":
        ok, reason = evaluate_exhaustion_gate(
            attempts=args.attempts,
            combos_tested=args.combos_tested,
            combos_remaining=args.combos_remaining,
            encoding_steps=args.encoding_steps,
            differential_evidence=args.differential_evidence,
            hard_blocker=args.hard_blocker,
        )
        status = "PASS" if ok else "FAIL"
        print(f"EXHAUSTION_GATE: {status}")
        print(f"REASON: {reason}")
        sys.exit(0 if ok else 2)
    elif args.command == "record-outcome":
        telemetry_path = Path(args.telemetry_path) if args.telemetry_path else Path(".autonomy-telemetry.json")
        # Serialise read-modify-write so parallel autopilot subagents can't
        # lose outcomes. Atomic write happens inside save_telemetry.
        with locked_file(telemetry_path):
            telemetry = load_telemetry(telemetry_path)
            telemetry = record_hunt_outcome(
                vuln_class=args.vuln_class,
                result=args.result,
                attempts=args.attempts,
                elapsed_minutes=args.elapsed_minutes,
                telemetry=telemetry,
            )
            save_telemetry(telemetry, telemetry_path)
        klass = _canonicalize_vuln_label(args.vuln_class) or args.vuln_class.strip().lower()
        row = telemetry.get("by_class", {}).get(klass, {})
        print(
            f"📈 telemetry updated: {klass} "
            f"(events={row.get('events', 0)} confirmed={row.get('confirmed', 0)} "
            f"killed={row.get('killed', 0)} partial={row.get('partial', 0)})"
        )
        sys.exit(0)
    elif args.command == "chain-plan":
        output = Path(args.output) if args.output else None
        sys.exit(
            show_chain_plan(
                capabilities_file=Path(args.capability_file),
                output=output,
                limit=args.limit,
            )
        )
    elif args.command == "evidence-score":
        result = evidence_sufficiency_score(
            has_http_pair=args.has_http_pair,
            has_readback=args.has_readback,
            has_browser_verification=args.has_browser_verification,
            reliability_runs=args.reliability_runs,
            reliability_hits=args.reliability_hits,
            has_harm_artifact=args.has_harm_artifact,
            chain_depth=args.chain_depth,
        )
        print(
            f"EVIDENCE_SCORE: {result['score']}  DECISION: {result['decision']}"
        )
        if result["notes"]:
            print("NOTES:")
            for note in result["notes"]:
                print(f"- {note}")
        sys.exit(0 if result["decision"] == "PASS" else 2)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
