#!/usr/bin/env python3
"""
chain_plan.py — generate per-finding chain plan dump.

Reads findings.json, the brain capability graph, and recon outputs;
emits `evidence/<target>/CHAIN_PLAN.md` listing 3-5 candidate next-links
per CONFIRMED finding plus the suggested agent for each link.

Usage:
    python3 tools/chain_plan.py <target>
    python3 tools/chain_plan.py            # all targets in findings.json

Read by:
    - /resume (surfaces chain plan at session start)
    - autopilot (dispatches against the plan in --paranoid/--normal)
    - recon-ranker (re-prioritizes surface based on chain-feeder findings)

The plan is the orchestrator's pre-loaded mental model: "you've got
these confirmed findings; here's what to chain into; here's which
agent to dispatch." A→B→C→… until terminal impact.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

FINDINGS_FILE = Path("findings.json")
BRAIN_DIR = Path(".claude/agent-memory-local/brain")
EVIDENCE_DIR = Path("evidence")

# Per-class chain anchors mirror rules/chain-table.md "Per-Class Chain
# Anchors" section. Each entry: {class -> [(anchor_description, agent)]}.
# Keep in sync with chain-table.md.
ANCHORS_BY_CLASS: dict[str, list[tuple[str, str]]] = {
    "open-redirect": [
        ("OAuth `redirect_uri` reflection — try `redirect_uri=<your-domain>`; if auth code delivered, ATO chain confirmed", "oauth-hunter"),
        ("`returnTo` / `next` / `continue` post-auth (CVE-2025-67716 Auth0 nextjs-auth0 pattern) — try `returnTo=javascript:alert(document.cookie)`", "oauth-hunter"),
        ("SAML RelayState / OIDC `post_logout_redirect_uri` — try `RelayState=<svg onload=...>`", "oauth-hunter"),
        ("Login flow CSRF anchor — does redirect happen post-login? Self-XSS on redirect target + login CSRF = ATO", "csrf-hunter + xss-hunter"),
        ("Cookie tossing prerequisite — does redirect target a sibling subdomain you control?", "subdomain-takeover + auth-tester"),
    ],
    "cors": [
        ("Credentialed authenticated endpoint — find `Access-Control-Allow-Credentials: true`; without this, CORS misconfig is informational", "cors-hunter"),
        ("Sensitive data endpoint — does over-permissive origin reach `/api/me`, `/api/users/<id>`, billing, secrets? Document exfil", "idor-hunter"),
        ("Origin reflection + `null` origin — sandboxed iframe / data: URI bypasses", "cors-hunter"),
        ("Subdomain wildcard regex flaw — `https://target.com.attacker.com`, `https://nottarget.com`", "cors-hunter"),
        ("Cross-origin postMessage handler — find unvalidated `addEventListener('message',...)` and abuse as data-theft sink", "xss-hunter"),
    ],
    "info-disclosure": [
        ("Bundle/source/config containing OAuth secrets → client_secret + missing PKCE = code interception chain", "oauth-hunter"),
        ("Stack trace revealing internal IPs / service names → SSRF target list", "ssrf-hunter"),
        ("Debug endpoint returning request headers / session tokens → IDOR / session fixation", "idor-hunter + auth-tester"),
        ("`.git`, `.env`, `backup.tar.gz`, `wp-config.php`, `phpinfo`, `/server-status` → DB creds / signing keys / cloud creds", "privilege-escalation + oauth-hunter"),
        ("Cloud metadata reachable via XSS context (window.fetch to 169.254.169.254) → IMDS theft", "xss-hunter"),
        ("API key in JS bundle with active scope — verify scope; if cross-user data → IDOR-via-key", "idor-hunter"),
    ],
    "csrf": [
        ("CSRF on password / email / phone change → ATO chain (changes the recovery vector)", "auth-tester"),
        ("CSRF on MFA disable / second-factor enrollment → MFA bypass", "business-logic + auth-tester"),
        ("CSRF on role change / permission grant / team invite → privilege escalation", "privilege-escalation"),
        ("CSRF on payment-method change / withdrawal address → financial impact", "business-logic"),
        ("CSRF on OAuth client registration / API key creation → backdoor-credential chain", "oauth-hunter"),
    ],
    "subdomain-takeover": [
        ("Subdomain is OAuth `redirect_uri` / SAML ACS / OIDC issuer — claim → ATO chain", "oauth-hunter"),
        ("Parent domain shares cookies (`.target.com`) → cookie tossing → session fixation → ATO", "auth-tester"),
        ("Subdomain has wildcard cert → MitM / TLS-confusion chain", "config-auditor"),
        ("Subdomain referenced from prod domain JS (CDN, asset, config) → trusted-domain phishing", "info-disclosure"),
        ("Subdomain in CSP `script-src` → CSP bypass on parent → stored XSS escalation", "xss-hunter"),
    ],
    "xxe": [
        ("SSRF via XXE → cloud metadata (SYSTEM 'http://169.254.169.254/...') → IAM creds", "ssrf-hunter"),
        ("OOB exfil to attacker DTD → blind XXE on cookie/config/private files", "xxe-hunter"),
        ("SAML XXE (assertion parsing) → authentication bypass via signed-assertion forgery", "oauth-hunter"),
        ("DOCX / XLSX / SVG XXE upload — payload survives upload pipeline → triggers in admin viewer", "file-upload + xss-hunter"),
        ("PHP wrapper / Java JNDI — `php://filter`, `jar://`, `ldap://` for source code / classloader RCE", "rce-hunter"),
    ],
    "file-upload": [
        ("Upload to web root + executable → web shell → RCE", "rce-hunter"),
        ("Upload SVG / HTML rendered inline → stored XSS in viewer context", "xss-hunter"),
        ("Path traversal in filename → overwrite config / cron / .ssh/authorized_keys → privesc / RCE", "rce-hunter + privilege-escalation"),
        ("Upload metadata renders in admin panel (filename, EXIF) → stored XSS in admin context → ATO", "xss-hunter"),
        ("Upload triggers server-side processor (PDF, image resize, AV) → SSRF / RCE via processor CVE", "rce-hunter + ssrf-hunter"),
    ],
    "race-condition": [
        ("Race on financial action (transfer, withdrawal, balance debit) → quantify $", "business-logic"),
        ("Race on coupon / gift-card / referral redemption → quantify (free-product × N)", "business-logic"),
        ("Race on one-shot tokens (password-reset, invite-accept, MFA-enrollment) → ATO if redeemed twice", "auth-tester"),
        ("Race on file write check → TOCTOU → privilege escalation / RCE", "rce-hunter + privilege-escalation"),
        ("Race on rate-limit / quota check → bypass quota → mass enumeration → IDOR amplification", "idor-hunter"),
    ],
    "business-logic": [
        ("Public archive / share-with-admin trigger (listmonk pattern) — manipulated artifact → admin-context render", "xss-hunter"),
        ("State carries to other context — manipulated price stored server-side → admin panel source-of-truth", "xss-hunter + privilege-escalation"),
        ("Workflow skip → access feature you didn't pay for — quantify ($premium × users)", "business-logic"),
        ("Negative / huge values → integer overflow / sign flip → financial chain", "business-logic"),
        ("Time-of-check / time-of-use on balance → race-condition chain", "race-condition"),
    ],
    "privilege-escalation": [
        ("Mass-assignment to set role/permission/tenant — does escalated account see other-tenant data? → IDOR amplification", "idor-hunter"),
        ("JWT claim manipulation works — verify which other claims are unprotected (sub, aud, iss) → cross-tenant chain", "oauth-hunter"),
        ("Admin endpoint reachable but rate-limited — confirm full admin actions, not just GET", "privilege-escalation"),
        ("Forced-browsing admin URL works → check write operations (DELETE, PATCH) too", "privilege-escalation"),
        ("HTTP method override → bypass auth — try same trick on every other admin endpoint", "auth-tester"),
    ],
}

# Vuln-class fingerprints — title / vuln_type / weakness substrings → class.
# Ordered: more specific first.
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

ACTIVE_STATUSES = {
    "confirmed", "potential", "submitted", "triaged", "resolved",
    "reported", "new", "open", "validated",
}


def _read_findings() -> list[dict]:
    """Return list of finding dicts, normalizing list-vs-dict schemas."""
    if not FINDINGS_FILE.exists():
        return []
    try:
        data = json.loads(FINDINGS_FILE.read_text())
    except json.JSONDecodeError:
        return []
    raw = data.get("findings", [])
    if isinstance(raw, dict):
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
    status = str(finding.get("status", "")).lower().strip()
    if not status:
        return True
    if status in ACTIVE_STATUSES:
        return True
    if any(skip in status for skip in ("withdraw", "duplicate", "n/a", "n-a", "draft", "rejected", "spam")):
        return False
    return False


def _has_chain_marker(finding: dict) -> bool:
    if any(finding.get(k) for k in ("chain_id", "chained_with", "chain")):
        return True
    notes = str(finding.get("notes", "")).lower() + str(finding.get("description", "")).lower()
    return "chain-candidate" in notes or "chain confirmed" in notes


def _finding_target(finding: dict) -> str:
    """Best-effort target extraction."""
    for key in ("target", "asset", "host", "domain", "program"):
        v = finding.get(key)
        if v:
            return str(v)
    return "unknown"


def _read_capability_graph() -> dict:
    cg = BRAIN_DIR / "patterns" / "capability-graph.json"
    if not cg.exists():
        return {}
    try:
        return json.loads(cg.read_text())
    except json.JSONDecodeError:
        return {}


def _capabilities_for_target(graph: dict, target: str) -> list[str]:
    """Return capability labels with at least one observation matching target."""
    nodes = graph.get("nodes", {})
    out = []
    for label, node in nodes.items():
        for obs in node.get("observations", []) or []:
            if str(obs.get("target", "")).lower() == target.lower():
                out.append(label)
                break
    return out


def _build_plan(findings: list[dict], graph: dict, target_filter: str | None) -> dict[str, list[dict]]:
    """Group plan entries by target."""
    plan: dict[str, list[dict]] = {}
    for f in findings:
        if not _is_active(f):
            continue
        if _has_chain_marker(f):
            continue
        cls = _classify(f)
        if cls is None or cls not in ANCHORS_BY_CLASS:
            continue
        target = _finding_target(f)
        if target_filter and target.lower() != target_filter.lower():
            continue
        anchors = ANCHORS_BY_CLASS[cls]
        capabilities = _capabilities_for_target(graph, target)
        plan.setdefault(target, []).append({
            "id": str(f.get("id") or f.get("report_id") or f.get("title", "?"))[:80],
            "title": str(f.get("title", ""))[:200],
            "class": cls,
            "severity": str(f.get("severity", "")).lower() or "?",
            "anchors": anchors,
            "capabilities": capabilities,
        })
    return plan


def _render(plan: dict[str, list[dict]]) -> dict[Path, str]:
    """Render one CHAIN_PLAN.md per target."""
    out: dict[Path, str] = {}
    if not plan:
        return out
    for target, entries in plan.items():
        path = EVIDENCE_DIR / target / "CHAIN_PLAN.md"
        lines = [
            f"# Chain Plan — {target}",
            "",
            f"_Generated: {datetime.now().isoformat(timespec='seconds')}_",
            "",
            "Per-finding chain candidates. Each entry lists the confirmed",
            "feeder finding and 3-5 candidate next-links with the suggested",
            "specialist agent to dispatch. Source-of-truth: `rules/chain-table.md`.",
            "",
            f"Pending feeder findings on this target: **{len(entries)}**",
            "",
        ]
        for i, e in enumerate(entries, 1):
            lines += [
                f"## {i}. `{e['id']}` ({e['class']}, {e['severity']})",
                "",
                f"**Title:** {e['title']}",
                "",
                "**Chain anchors to probe:**",
                "",
            ]
            for anchor, agent in e["anchors"]:
                lines += [f"- {anchor}", f"  - Dispatch: `{agent}`"]
            if e["capabilities"]:
                lines += [
                    "",
                    "**Capability graph context (already mapped on this target):**",
                    "",
                ]
                for cap in e["capabilities"][:8]:
                    lines.append(f"- {cap}")
            lines.append("")
        out[path] = "\n".join(lines) + "\n"
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate per-finding chain plan dump")
    parser.add_argument("target", nargs="?", help="filter to one target (default: all)")
    parser.add_argument("--quiet", action="store_true", help="suppress info output")
    args = parser.parse_args()

    findings = _read_findings()
    if not findings:
        if not args.quiet:
            print("chain_plan: no findings.json (or empty); nothing to plan.", file=sys.stderr)
        return 0

    graph = _read_capability_graph()
    plan = _build_plan(findings, graph, args.target)

    if not plan:
        if not args.quiet:
            print(
                "chain_plan: no pending feeder findings (all feeders have "
                "chain markers or no feeders detected).",
                file=sys.stderr,
            )
        return 0

    rendered = _render(plan)
    for path, body in rendered.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
        if not args.quiet:
            entries = plan.get(path.parent.name, [])
            print(f"chain_plan: wrote {path} ({len(entries)} entry/entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
