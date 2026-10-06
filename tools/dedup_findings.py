#!/usr/bin/env python3
"""
dedup_findings.py — Deduplicate and manage security findings.

Reads findings from various scanner outputs, deduplicates them,
and produces a unified findings database in JSON format.

Usage:
    python3 dedup_findings.py --scan-dir scans/ --output findings.json
    python3 dedup_findings.py --add finding.json --db findings.json
    python3 dedup_findings.py --stats --db findings.json
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


def normalize_url(url: str) -> str:
    """Normalize URL for comparison — strip fragments, trailing slashes, sort params."""
    url = url.split("#")[0].rstrip("/")
    if "?" in url:
        base, params = url.split("?", 1)
        sorted_params = "&".join(sorted(params.split("&")))
        return f"{base}?{sorted_params}"
    return url


def finding_fingerprint(finding: dict) -> str:
    """Generate a dedup fingerprint for a finding."""
    # Key fields for deduplication
    components = [
        finding.get("type", "").lower(),
        normalize_url(finding.get("url", finding.get("endpoint", ""))),
        finding.get("parameter", ""),
        finding.get("cwe", ""),
    ]
    raw = "|".join(str(c) for c in components)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def parse_nuclei_output(path: Path) -> list[dict]:
    """Parse nuclei JSON output."""
    findings = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            findings.append({
                "type": entry.get("info", {}).get("name", "Unknown"),
                "severity": entry.get("info", {}).get("severity", "unknown"),
                "url": entry.get("matched-at", entry.get("host", "")),
                "template": entry.get("template-id", ""),
                "matcher_name": entry.get("matcher-name", ""),
                "description": entry.get("info", {}).get("description", ""),
                "reference": entry.get("info", {}).get("reference", []),
                "cwe": ",".join(str(c) for c in entry.get("info", {}).get("classification", {}).get("cwe-id", [])),
                "source": "nuclei",
                "raw_file": str(path),
                "timestamp": entry.get("timestamp", datetime.now(timezone.utc).isoformat()),
            })
        except json.JSONDecodeError:
            # Try to parse nuclei text format
            # [vuln-id] [severity] url
            match = re.match(r"\[([^\]]+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\]\s*(.*)", line)
            if match:
                findings.append({
                    "type": match.group(1),
                    "severity": match.group(2),
                    "url": match.group(4).strip(),
                    "template": match.group(1),
                    "source": "nuclei",
                    "raw_file": str(path),
                })
    return findings


def parse_generic_json(path: Path) -> list[dict]:
    """Parse a generic JSON findings file."""
    data = json.loads(path.read_text())
    if isinstance(data, list):
        return data
    elif isinstance(data, dict) and "findings" in data:
        return data["findings"]
    elif isinstance(data, dict):
        return [data]
    return []


def load_findings_db(db_path: Path) -> dict:
    """Load the findings database."""
    if db_path.exists():
        return json.loads(db_path.read_text())
    return {
        "metadata": {
            "created": datetime.now(timezone.utc).isoformat(),
            "version": 1,
        },
        "findings": {},
        "stats": {
            "total": 0,
            "duplicates_skipped": 0,
        },
    }


def save_findings_db(db: dict, db_path: Path):
    """Save the findings database."""
    db["metadata"]["updated"] = datetime.now(timezone.utc).isoformat()
    db["stats"]["total"] = len(db["findings"])
    db_path.write_text(json.dumps(db, indent=2))


def add_findings(db: dict, findings: list[dict]) -> tuple[int, int]:
    """Add findings to the database, deduplicating. Returns (added, skipped)."""
    added = 0
    skipped = 0
    for finding in findings:
        fp = finding_fingerprint(finding)
        if fp in db["findings"]:
            # Update existing finding if new one has more info
            existing = db["findings"][fp]
            existing.setdefault("seen_count", 1)
            existing["seen_count"] += 1
            existing.setdefault("sources", [])
            src = finding.get("source", "unknown")
            if src not in existing["sources"]:
                existing["sources"].append(src)
            skipped += 1
        else:
            finding["fingerprint"] = fp
            finding["seen_count"] = 1
            finding["sources"] = [finding.get("source", "unknown")]
            finding["added"] = datetime.now(timezone.utc).isoformat()
            finding.setdefault("status", "new")
            db["findings"][fp] = finding
            added += 1
    return added, skipped


def scan_directory(scan_dir: Path) -> list[dict]:
    """Scan a directory for findings files."""
    all_findings = []

    for path in scan_dir.rglob("*"):
        if not path.is_file():
            continue
        try:
            if path.suffix == ".json":
                if "nuclei" in path.name.lower() or "nuclei" in str(path.parent).lower():
                    all_findings.extend(parse_nuclei_output(path))
                else:
                    all_findings.extend(parse_generic_json(path))
            elif path.suffix in (".txt", ".log"):
                # Try nuclei text format
                all_findings.extend(parse_nuclei_output(path))
        except Exception as e:
            print(f"  Warning: Failed to parse {path}: {e}", file=sys.stderr)

    return all_findings


def print_stats(db: dict):
    """Print findings statistics."""
    findings = db["findings"].values()
    total = len(findings)
    by_severity = {}
    by_type = {}
    by_status = {}

    for f in findings:
        sev = f.get("severity", "unknown").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1
        ftype = f.get("type", "unknown")
        by_type[ftype] = by_type.get(ftype, 0) + 1
        status = f.get("status", "new")
        by_status[status] = by_status.get(status, 0) + 1

    print(f"\n📊 Findings Database Statistics")
    print(f"   Total unique findings: {total}")
    print(f"   Duplicates skipped (lifetime): {db['stats'].get('duplicates_skipped', 0)}")
    print()

    severity_order = ["critical", "high", "medium", "low", "info", "informational", "unknown"]
    severity_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪", "informational": "⚪", "unknown": "⚫"}

    print("   By Severity:")
    for sev in severity_order:
        if sev in by_severity:
            icon = severity_icons.get(sev, "⚫")
            print(f"     {icon} {sev}: {by_severity[sev]}")

    print(f"\n   By Status:")
    for status, count in sorted(by_status.items()):
        print(f"     {status}: {count}")

    if len(by_type) <= 20:
        print(f"\n   By Type:")
        for ftype, count in sorted(by_type.items(), key=lambda x: -x[1]):
            print(f"     {ftype}: {count}")


def main():
    parser = argparse.ArgumentParser(description="Deduplicate and manage security findings")
    parser.add_argument("--scan-dir", help="Directory with scan results to import")
    parser.add_argument("--add", help="Add a single finding JSON file")
    parser.add_argument("--db", "--output", dest="db", default="findings.json", help="Findings database path")
    parser.add_argument("--stats", action="store_true", help="Show statistics")
    parser.add_argument("--export-csv", help="Export findings to CSV")
    parser.add_argument("--severity", help="Filter by severity (for export)")
    parser.add_argument("--mark", nargs=2, metavar=("FINGERPRINT", "STATUS"),
                       help="Mark a finding's status (new/confirmed/false-positive/reported/fixed)")
    args = parser.parse_args()

    db_path = Path(args.db)
    db = load_findings_db(db_path)

    if args.scan_dir:
        scan_path = Path(args.scan_dir)
        if not scan_path.exists():
            print(f"ERROR: Scan directory not found: {args.scan_dir}", file=sys.stderr)
            sys.exit(1)
        print(f"Scanning {scan_path}...")
        findings = scan_directory(scan_path)
        added, skipped = add_findings(db, findings)
        db["stats"]["duplicates_skipped"] = db["stats"].get("duplicates_skipped", 0) + skipped
        save_findings_db(db, db_path)
        print(f"  Added: {added}, Duplicates skipped: {skipped}")

    if args.add:
        path = Path(args.add)
        findings = parse_generic_json(path)
        added, skipped = add_findings(db, findings)
        db["stats"]["duplicates_skipped"] = db["stats"].get("duplicates_skipped", 0) + skipped
        save_findings_db(db, db_path)
        print(f"  Added: {added}, Duplicates skipped: {skipped}")

    if args.mark:
        fp, status = args.mark
        valid_statuses = ("new", "confirmed", "false-positive", "reported", "fixed", "duplicate")
        if status not in valid_statuses:
            print(f"ERROR: Invalid status. Valid: {', '.join(valid_statuses)}", file=sys.stderr)
            sys.exit(1)
        if fp in db["findings"]:
            db["findings"][fp]["status"] = status
            save_findings_db(db, db_path)
            print(f"  Marked {fp} as {status}")
        else:
            # Try prefix match
            matches = [k for k in db["findings"] if k.startswith(fp)]
            if len(matches) == 1:
                db["findings"][matches[0]]["status"] = status
                save_findings_db(db, db_path)
                print(f"  Marked {matches[0]} as {status}")
            elif len(matches) > 1:
                print(f"  Ambiguous fingerprint prefix. Matches: {matches}")
            else:
                print(f"  Finding not found: {fp}")

    if args.export_csv:
        import csv
        findings = list(db["findings"].values())
        if args.severity:
            findings = [f for f in findings if f.get("severity", "").lower() == args.severity.lower()]
        with open(args.export_csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["fingerprint", "type", "severity", "url", "status", "description", "cwe"])
            writer.writeheader()
            for finding in findings:
                writer.writerow({k: finding.get(k, "") for k in writer.fieldnames})
        print(f"  Exported {len(findings)} findings to {args.export_csv}")

    if args.stats:
        print_stats(db)

    if not any([args.scan_dir, args.add, args.stats, args.export_csv, args.mark]):
        parser.print_help()


if __name__ == "__main__":
    main()


# --- I5: Cross-reference hacktivity for duplicates ---

def check_hacktivity_dupes(finding_desc: str, hacktivity_path: Path = None) -> list[str]:
    """Check if a finding matches disclosed reports in hacktivity.md"""
    if hacktivity_path is None:
        hacktivity_path = Path("hacktivity.md")
    if not hacktivity_path.exists():
        return []

    matches = []
    desc_lower = finding_desc.lower()
    keywords = [w for w in desc_lower.split() if len(w) > 3]

    for line in hacktivity_path.read_text().splitlines():
        if not line.startswith("- ["):
            continue
        line_lower = line.lower()
        score = sum(1 for kw in keywords if kw in line_lower)
        if score >= 2:  # At least 2 keyword matches
            matches.append(line.strip())

    return matches
