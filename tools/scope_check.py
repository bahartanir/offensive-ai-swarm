#!/usr/bin/env python3
"""
scope_check.py — Target scope validation tool for pentest agents.

Validates whether a given target (domain, URL, IP, CIDR) is within the
authorized testing scope. Reads from local scope files and optionally
from bug bounty platform APIs.

Usage:
    python3 scope_check.py <target> [--scope-file PATH] [--program PROGRAM_NAME]
    python3 scope_check.py example.com
    python3 scope_check.py https://api.example.com/v1/users
    python3 scope_check.py 192.168.1.50 --scope-file scope.yaml
"""

import argparse
import ipaddress
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def parse_target(target: str) -> dict:
    """Extract hostname/IP from various target formats."""
    # Try as URL first
    if "://" in target:
        parsed = urlparse(target)
        return {
            "original": target,
            "type": "url",
            "hostname": parsed.hostname or "",
            "port": parsed.port,
            "path": parsed.path,
            "scheme": parsed.scheme,
        }

    # Try as IP/CIDR
    try:
        net = ipaddress.ip_network(target, strict=False)
        return {
            "original": target,
            "type": "cidr" if "/" in target else "ip",
            "hostname": str(net.network_address) if "/" in target else target,
            "network": net,
        }
    except ValueError:
        pass

    # Treat as domain
    # Strip any trailing dot, port, or path fragments
    domain = target.split("/")[0].split(":")[0].rstrip(".")
    return {
        "original": target,
        "type": "domain",
        "hostname": domain,
    }


def match_wildcard_domain(pattern: str, hostname: str) -> bool:
    """Match a wildcard domain pattern against a hostname.

    *.example.com matches sub.example.com and deep.sub.example.com
    but does NOT match example.com itself.
    """
    pattern = pattern.strip().lower()
    hostname = hostname.strip().lower()

    if pattern.startswith("*."):
        base = pattern[2:]
        # Must be a subdomain of base, not base itself
        return hostname.endswith("." + base) or hostname == base
    else:
        return hostname == pattern


def match_cidr(pattern: str, target: dict) -> bool:
    """Check if target IP falls within a CIDR range."""
    try:
        network = ipaddress.ip_network(pattern, strict=False)
        if target["type"] == "ip":
            return ipaddress.ip_address(target["hostname"]) in network
        elif target["type"] == "cidr":
            return target["network"].subnet_of(network)
    except (ValueError, KeyError):
        pass
    return False


def load_scope_txt(path: Path) -> dict:
    """Parse a .scope.txt file."""
    in_scope = []
    out_of_scope = []
    current_section = None

    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            lower = line.lower()
            if "in scope" in lower or "in-scope" in lower:
                current_section = "in"
            elif "out of scope" in lower or "out-of-scope" in lower:
                current_section = "out"
            continue

        # Strip inline comments — the sync tool writes lines like
        # "foo.com  # notes", and without this the matcher never hits.
        line = line.split("#", 1)[0].strip()
        if not line:
            continue

        if current_section == "out":
            out_of_scope.append(line)
        elif current_section == "in":
            in_scope.append(line)
        else:
            # Default to in-scope if no section header
            in_scope.append(line)

    return {"in_scope": in_scope, "out_of_scope": out_of_scope, "source": str(path)}


_SECTION_RE = re.compile(r"^([a-zA-Z_][a-zA-Z0-9_]*):\s*(?:#.*)?$")
_ASSET_RE = re.compile(r"""^\s*-\s*asset:\s*["']?([^"'#\n]+?)["']?\s*(?:#.*)?$""")


def _load_scope_yaml_fallback(path: Path) -> dict:
    """Section-aware parser for scope.yaml when PyYAML is unavailable.

    The previous fallback dumped every ``asset:`` value into ``in_scope``
    and left ``out_of_scope`` empty, which silently disabled deny rules.
    """
    text = path.read_text()
    if re.search(r"^scope_mode:\s*['\"]?placeholder['\"]?\s*(?:#.*)?$", text, re.M):
        program_match = re.search(r"^program:\s*['\"]?([^'\"\n]+)['\"]?\s*(?:#.*)?$", text, re.M)
        return {
            "placeholder": True,
            "in_scope": [],
            "out_of_scope": [],
            "notes": [],
            "program": program_match.group(1).strip() if program_match else "",
            "source": str(path),
        }

    in_scope: list[str] = []
    out_of_scope: list[str] = []
    current: list[str] | None = None

    for line in text.splitlines():
        section = _SECTION_RE.match(line)
        if section:
            name = section.group(1)
            if name == "in_scope":
                current = in_scope
            elif name == "out_of_scope":
                current = out_of_scope
            else:
                current = None
            continue

        if current is None:
            continue

        match = _ASSET_RE.match(line)
        if match:
            current.append(match.group(1).strip())

    return {"in_scope": in_scope, "out_of_scope": out_of_scope, "source": str(path)}


def load_scope_yaml(path: Path) -> dict:
    """Parse a scope.yaml file.

    Returns ``{"placeholder": True, ...}`` if the file carries the
    ``scope_mode: placeholder`` sentinel emitted by ``sync_program`` when
    the platform API returned no scope data. Callers must treat the
    placeholder state identically to NO_SCOPE_FILE — NEVER as "empty scope
    means everything is out-of-scope by default" and NEVER as "empty scope
    means everything is in-scope". An incomplete scope is a hard stop.
    """
    if not HAS_YAML:
        return _load_scope_yaml_fallback(path)

    data = yaml.safe_load(path.read_text()) or {}
    if str(data.get("scope_mode", "")).strip().lower() == "placeholder":
        return {
            "placeholder": True,
            "in_scope": [],
            "out_of_scope": [],
            "notes": [],
            "program": str(data.get("program", "")),
            "source": str(path),
        }

    in_scope = []
    out_of_scope = []
    notes = data.get("notes", [])

    for item in data.get("in_scope", []):
        if isinstance(item, dict):
            asset = item.get("asset", "")
            if item.get("eligible", True):
                in_scope.append(asset)
        else:
            in_scope.append(str(item))

    for item in data.get("out_of_scope", []):
        if isinstance(item, dict):
            out_of_scope.append(item.get("asset", ""))
        else:
            out_of_scope.append(str(item))

    return {
        "in_scope": in_scope,
        "out_of_scope": out_of_scope,
        "notes": notes,
        "program": data.get("program", ""),
        "source": str(path),
    }


def load_scope_md(path: Path) -> dict:
    """Parse a SCOPE.md file — extract domains/IPs from bullet points."""
    in_scope = []
    out_of_scope = []
    current_section = "in"

    for line in path.read_text().splitlines():
        lower = line.lower().strip()
        if "out of scope" in lower or "out-of-scope" in lower:
            current_section = "out"
            continue
        elif "in scope" in lower or "in-scope" in lower:
            current_section = "in"
            continue

        # Extract from bullet points or bare lines
        match = re.match(r"^[\s*\-+]*\s*`?([a-zA-Z0-9*.\-/:]+)`?\s*", line)
        if match:
            candidate = match.group(1).strip()
            if "." in candidate or "/" in candidate:
                if current_section == "out":
                    out_of_scope.append(candidate)
                else:
                    in_scope.append(candidate)

    return {"in_scope": in_scope, "out_of_scope": out_of_scope, "source": str(path)}


def find_scope_file(start_dir: Path = None) -> dict | None:
    """Search for scope files in the project."""
    search_dir = start_dir or Path.cwd()

    candidates = [
        (".scope.txt", load_scope_txt),
        ("scope.txt", load_scope_txt),
        ("scope.yaml", load_scope_yaml),
        ("scope.yml", load_scope_yaml),
        ("SCOPE.md", load_scope_md),
    ]

    for filename, loader in candidates:
        path = search_dir / filename
        if path.exists():
            return loader(path)

    return None


def check_scope(target_str: str, scope: dict) -> dict:
    """Check a target against scope rules. Returns verdict."""
    target = parse_target(target_str)
    hostname = target.get("hostname", "")

    # Placeholder sentinel from sync_program: platform API returned no
    # scope data, so we have no authority to answer. Refuse every target —
    # this matches the NO_SCOPE_FILE behaviour and prevents testing against
    # a scope that doesn't actually exist yet.
    if scope.get("placeholder"):
        return {
            "target": target_str,
            "status": "NO_SCOPE_FILE",
            "matched_rule": None,
            "source": scope.get("source", "unknown"),
            "message": (
                "scope.yaml is a placeholder (sync_program could not fetch scope "
                "from the platform API). Populate scope manually or re-run sync "
                "with working credentials before testing."
            ),
        }

    # Check out-of-scope FIRST (deny wins)
    for pattern in scope.get("out_of_scope", []):
        if match_wildcard_domain(pattern, hostname):
            return {
                "target": target_str,
                "status": "OUT_OF_SCOPE",
                "matched_rule": pattern,
                "rule_type": "out_of_scope",
                "source": scope.get("source", "unknown"),
            }
        if target["type"] in ("ip", "cidr") and match_cidr(pattern, target):
            return {
                "target": target_str,
                "status": "OUT_OF_SCOPE",
                "matched_rule": pattern,
                "rule_type": "out_of_scope",
                "source": scope.get("source", "unknown"),
            }

    # Check in-scope
    for pattern in scope.get("in_scope", []):
        if match_wildcard_domain(pattern, hostname):
            return {
                "target": target_str,
                "status": "IN_SCOPE",
                "matched_rule": pattern,
                "rule_type": "in_scope",
                "source": scope.get("source", "unknown"),
                "notes": scope.get("notes", []),
            }
        if target["type"] in ("ip", "cidr") and match_cidr(pattern, target):
            return {
                "target": target_str,
                "status": "IN_SCOPE",
                "matched_rule": pattern,
                "rule_type": "in_scope",
                "source": scope.get("source", "unknown"),
                "notes": scope.get("notes", []),
            }

    return {
        "target": target_str,
        "status": "UNCERTAIN",
        "matched_rule": None,
        "source": scope.get("source", "unknown"),
        "message": "Target did not match any scope rule. Treat as out-of-scope until confirmed.",
    }


def main():
    parser = argparse.ArgumentParser(description="Validate target scope for security testing")
    parser.add_argument("target", nargs="?", default=None, help="Target to validate (domain, URL, IP, CIDR)")
    parser.add_argument("--scope-file", help="Path to scope file", default=None)
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--batch", help="File with one target per line", default=None)
    parser.add_argument("--list", action="store_true", help="List all in-scope targets from scope file")
    args = parser.parse_args()

    # Load scope
    scope = None
    if args.scope_file:
        path = Path(args.scope_file)
        if not path.exists():
            print(f"ERROR: Scope file not found: {args.scope_file}", file=sys.stderr)
            sys.exit(1)
        ext = path.suffix.lower()
        if ext in (".yaml", ".yml"):
            scope = load_scope_yaml(path)
        elif ext == ".md":
            scope = load_scope_md(path)
        else:
            scope = load_scope_txt(path)
    else:
        scope = find_scope_file()

    # --list mode: dump all in-scope targets
    if args.list:
        if scope is None:
            print("No scope file found.", file=sys.stderr)
            sys.exit(2)
        targets = scope.get("in_scope", [])
        if args.json:
            print(json.dumps({"source": scope.get("source", ""), "in_scope": targets, "out_of_scope": scope.get("out_of_scope", [])}))
        else:
            print(f"# In-scope targets ({len(targets)}) from {scope.get('source', 'unknown')}")
            for t in targets:
                print(t)
        sys.exit(0)

    # Normal mode requires a target
    if not args.target and not args.batch:
        parser.print_help()
        print("\nTip: use --list to show all in-scope targets from the scope file.")
        sys.exit(0)

    if scope is None:
        result = {
            "target": args.target or "",
            "status": "NO_SCOPE_FILE",
            "message": "No scope file found. Create .scope.txt or scope.yaml in the project root.",
        }
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"⚠  NO SCOPE FILE FOUND")
            print(f"   Create .scope.txt or scope.yaml in the project root.")
            print(f"   All targets treated as OUT OF SCOPE until scope is defined.")
        sys.exit(2)

    # Check targets
    targets = [args.target]
    if args.batch:
        targets = Path(args.batch).read_text().strip().splitlines()

    results = [check_scope(t.strip(), scope) for t in targets if t.strip()]

    if args.json:
        print(json.dumps(results if len(results) > 1 else results[0], indent=2))
    else:
        for r in results:
            status = r["status"]
            icon = {"IN_SCOPE": "✅", "OUT_OF_SCOPE": "🚫", "UNCERTAIN": "⚠ "}.get(status, "?")
            print(f"{icon} {r['target']}: {status}")
            if r.get("matched_rule"):
                print(f"   Rule: {r['matched_rule']}")
            if r.get("notes"):
                for note in r["notes"]:
                    print(f"   Note: {note}")
            if r.get("message"):
                print(f"   {r['message']}")

    # Exit code: 0=in_scope, 1=out_of_scope, 2=uncertain/no_scope
    if any(r["status"] == "OUT_OF_SCOPE" for r in results):
        sys.exit(1)
    elif any(r["status"] in ("UNCERTAIN", "NO_SCOPE_FILE") for r in results):
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
