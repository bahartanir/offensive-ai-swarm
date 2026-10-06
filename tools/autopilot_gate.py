#!/usr/bin/env python3
"""Hard pre-completion gate for the /autopilot skill.

The skill text is useful for orchestration, but completion must not depend on
an inline shell block that can only see targets the agent already decided to
record. This tool fails closed: live hosts that are not ranked, P1 targets
without complete A-I surface evidence, shallow coverage records, and generic
not-applicable claims all block completion.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


REQUIRED_CLASSES = [
    "idor",
    "xss-reflected",
    "xss-stored",
    "xss-dom",
    "ssrf",
    "sqli",
    "ssti",
    "rce",
    "oauth",
    "open-redirect",
    "csrf",
    "cors",
    "info-disclosure",
    "race-condition",
    "business-logic",
    "privilege-escalation",
    "file-upload",
    "xxe",
    "graphql",
    "subdomain-takeover",
    "llm-ai",
    "auth-bypass",
    "cache-deception",
    "header-injection",
    "h2-desync",
    "method-confusion",
]

SURFACE_DRIVEN_CLASSES = {
    "cache-deception": "C",
    "header-injection": "D",
    "h2-desync": "F",
    "method-confusion": "B",
}

FORBIDDEN_SUBSTITUTES = (
    "js-analyzer",
    "config-auditor",
    "waf-profiler",
    "sast-",
    "cloud-recon",
    "vuln-scanner",
)

SURFACE_ARTIFACTS = [
    ("A", "Path/file enumeration", ("discovery.txt",)),
    ("B", "HTTP method matrix", ("method-matrix.txt", "methods.txt")),
    ("C", "Cache deception", ("cache-deception.txt",)),
    ("D", "Header injection", ("header-injection.txt",)),
    ("E", "CORS preflight matrix", ("cors-matrix.txt",)),
    ("F", "HTTP/2 desync indicators", ("h2-desync.txt",)),
    ("G", "Subdomain takeover", ("takeover.txt", "subdomain-takeover.txt")),
    ("I", "SPA/hash routing seeds", ("spa-routing.txt",)),
]

CF_ARTIFACT = ("H", "Cloudflare-specific probes", ("cloudflare.txt", "cf-quirks.txt"))

COMPLETION_MARKER_NAME = ".complete"

HOST_RE = re.compile(
    r"(?:https?://)?(?:\*\.)?(?P<host>[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}(?::\d+)?)"
)
STATUS_LINE_RE = re.compile(r"^(?P<path>\S+)\s+(?P<status>[1-5][0-9]{2})\b")
METHOD_LINE_RE = re.compile(
    r"^(?P<method>OPTIONS|HEAD|GET|POST|PUT|PATCH|DELETE|TRACE|CONNECT|PROPFIND|COPY|MOVE|MKCOL|LOCK|UNLOCK)\s+"
    r"(?P<path>\S+):\s+(?P<status>[1-5][0-9]{2})\b",
    re.IGNORECASE,
)
ATTEMPT_RE = re.compile(
    r"(?:\battempts?\s*[:=]\s*(?P<n1>\d+)|(?P<n2>\d+)\s+distinct\s+attempts?)",
    re.IGNORECASE,
)
REMAINING_RE = re.compile(r"(?:combos?_)?remaining\s*[:=]\s*(?P<n>\d+)", re.IGNORECASE)
UNAUTH_WRITE_BRAIN_RE = re.compile(
    r"unauth-write\s*:\s*(?P<path>\S+)",
    re.IGNORECASE,
)
ADVERSARIAL_BATTERY_RE = re.compile(
    r"adversarial-battery\s*:\s*(?P<path>\S+)\s*(?:—|--|-)?(?P<details>.*?)(?=\n|$)",
    re.IGNORECASE,
)
EVIDENCE_PATH_RE = re.compile(
    r"evidence\s*[:=]\s*(?P<path>[^\s,;]+)",
    re.IGNORECASE,
)
UNAUTH_BATTERY_REQUIRED_DIMENSIONS = (
    "mass-assignment",
    "payload-fields",
    "id-collision",
    "race",
    "chain-anchors",
)
UNAUTH_BATTERY_MIN_ATTEMPTS = 10
UNAUTH_WRITE_SUCCESS_STATUSES = {
    "200",
    "201",
    "202",
    "204",
    "301",
    "302",
    "303",
    "307",
    "308",
}

RECON_DEPTH_ARTIFACTS = [
    ("dns-bruteforce", ("recon/dns-bruteforce.txt", "recon/dns-brute.txt")),
    ("urlscan-cdx", ("recon/urlscan-cdx.json", "recon/urlscan.json", "recon/cdx.json")),
    ("github-code", ("recon/github-code.json", "recon/github.json")),
    (
        "public-archives",
        ("recon/public-archives.txt", "recon/wayback.txt", "recon/archive-org.txt"),
    ),
]
RECON_SKIP_RE = re.compile(
    r"recon-skip\s*:\s*(?P<artifact>[\w-]+)\b.*?policy\s*[:=]?\s*(?P<clause>\S+)",
    re.IGNORECASE,
)
MOBILE_ASSET_KEYWORDS = (
    "mobile",
    "android",
    "ios",
    "apk",
    "ipa",
    "package",
)

CROSS_REGION_INFERENCE_RES = (
    re.compile(r"same[-_ ]code[-_ ]as[-_ ]\w+", re.IGNORECASE),
    re.compile(r"equivalent[-_ ]to[-_ ]\w+", re.IGNORECASE),
    re.compile(r"\w+[-_ ]hardened[-_ ]so", re.IGNORECASE),
    re.compile(r"assumed\b[^\n]*\bsame\b", re.IGNORECASE),
    re.compile(r"inferr?ed\b[^\n]*\bfrom\b[^\n]*\bregion\b", re.IGNORECASE),
)

GENERIC_HOST_PREFIXES = {
    "api",
    "www",
    "web",
    "auth",
    "admin",
    "cdn",
    "static",
    "app",
    "m",
    "mobile",
    "stage",
    "staging",
    "preprod",
    "qa",
    "dev",
    "test",
}


@dataclass(frozen=True)
class GateIssue:
    code: str
    message: str
    target: str = ""

    def format(self) -> str:
        prefix = f"{self.target}: " if self.target else ""
        return f"GATE FAIL [{self.code}]: {prefix}{self.message}"


@dataclass
class GateResult:
    issues: list[GateIssue] = field(default_factory=list)
    p1_targets: list[str] = field(default_factory=list)
    ranked_targets: dict[str, str] = field(default_factory=dict)
    live_hosts: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.issues

    def add(self, code: str, message: str, target: str = "") -> None:
        self.issues.append(GateIssue(code=code, message=message, target=target))


def slugify_target(target: str) -> str:
    return target.replace("://", "-").replace("/", "-").replace(".", "-").replace(":", "-").strip("-")


def normalize_target(raw: str) -> str:
    text = raw.strip().strip("`'\"")
    if not text or text.startswith("#"):
        return ""
    if "://" in text:
        parsed = urlparse(text)
        text = parsed.netloc or parsed.path
    text = text.strip().strip("/")
    if "/" in text:
        text = text.split("/", 1)[0]
    if text.startswith("*."):
        text = text[2:]
    if not text or "*" in text:
        return ""
    return text.lower()


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def _extract_hosts(text: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for match in HOST_RE.finditer(text):
        host = normalize_target(match.group("host"))
        if host and host not in seen:
            seen.add(host)
            out.append(host)
    return out


def _dedupe(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _parse_frontmatter_value(content: str, key: str) -> str:
    match = re.search(rf"^{re.escape(key)}:\s*(.+?)\s*$", content, flags=re.MULTILINE)
    if not match:
        return ""
    return match.group(1).strip().strip("'\"").lower()


def _brain_targets(brain_dir: Path) -> dict[str, dict[str, str]]:
    targets: dict[str, dict[str, str]] = {}
    targets_dir = brain_dir / "targets"
    for path in sorted(targets_dir.glob("*.md")):
        content = _read_text(path)
        target = _parse_frontmatter_value(content, "target") or path.stem
        target = normalize_target(target) or path.stem
        priority = _parse_frontmatter_value(content, "priority")
        targets[target] = {
            "path": str(path),
            "priority": priority,
            "slug": path.stem,
            "content": content,
        }
    return targets


def _collect_live_hosts(root: Path) -> list[str]:
    candidates = [
        root / "recon" / "live-hosts.txt",
        root / "recon" / "live_hosts.txt",
        root / "recon" / "alive.txt",
        root / "recon" / "hosts.txt",
        root / "live-hosts.txt",
    ]
    hosts: list[str] = []
    for path in candidates:
        if path.exists():
            hosts.extend(_extract_hosts(_read_text(path)))
    return _dedupe(hosts)


def _rank_from_line(line: str) -> str:
    if re.search(r"\bP1\b", line, flags=re.IGNORECASE):
        return "p1"
    if re.search(r"\bP2\b", line, flags=re.IGNORECASE):
        return "p2"
    if re.search(r"\bKILL\b", line, flags=re.IGNORECASE):
        return "kill"
    return ""


def _collect_ranked_targets(root: Path, brain: dict[str, dict[str, str]]) -> dict[str, str]:
    ranked: dict[str, str] = {}
    for target, meta in brain.items():
        priority = meta.get("priority", "")
        if priority in {"p1", "p2", "kill"}:
            ranked[target] = priority

    ranking_files = [
        root / "ATTACK_SURFACE_RANKING.md",
        root / "ATTACK_SURFACE_RANKING.json",
        root / "recon" / "ATTACK_SURFACE_RANKING.md",
        root / "recon" / "attack-surface-ranking.md",
        root / "recon" / "ranking.md",
    ]
    for path in ranking_files:
        if not path.exists():
            continue
        if path.suffix == ".json":
            try:
                data = json.loads(_read_text(path))
            except json.JSONDecodeError:
                continue
            rows = data if isinstance(data, list) else data.get("rows", [])
            for row in rows:
                if not isinstance(row, dict):
                    continue
                host = normalize_target(str(row.get("endpoint") or row.get("target") or row.get("host") or ""))
                bucket = str(row.get("bucket") or row.get("priority") or "").lower()
                if host and bucket in {"p1", "p2", "kill"}:
                    ranked[host] = bucket
            continue

        for line in _read_text(path).splitlines():
            rank = _rank_from_line(line)
            if not rank:
                continue
            for host in _extract_hosts(line):
                ranked[host] = rank
    return ranked


def _evidence_surface_dirs(root: Path, target: str, slug: str = "") -> list[Path]:
    candidates = [
        root / "evidence" / target / "surface",
        root / "evidence" / slugify_target(target) / "surface",
    ]
    if slug:
        candidates.append(root / "evidence" / slug / "surface")
    out: list[Path] = []
    seen: set[Path] = set()
    for path in candidates:
        if path not in seen:
            seen.add(path)
            out.append(path)
    return out


def _evidence_coverage_dirs(root: Path, target: str, slug: str = "") -> list[Path]:
    candidates = [
        root / "evidence" / target / "coverage",
        root / "evidence" / slugify_target(target) / "coverage",
    ]
    if slug:
        candidates.append(root / "evidence" / slug / "coverage")
    out: list[Path] = []
    seen: set[Path] = set()
    for path in candidates:
        if path not in seen:
            seen.add(path)
            out.append(path)
    return out


def _load_coverage_json(coverage_dirs: list[Path], vuln_class: str) -> tuple[dict | None, Path | None]:
    for coverage_dir in coverage_dirs:
        path = coverage_dir / f"{vuln_class}.json"
        if path.exists() and path.stat().st_size > 0:
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except json.JSONDecodeError:
                return None, path
            if isinstance(data, dict):
                return data, path
    return None, None


def _validate_coverage_json(vuln_class: str, record: dict, root: Path) -> list[str]:
    issues: list[str] = []
    if record.get("class") and record["class"] != vuln_class:
        issues.append(f"coverage JSON 'class' is {record['class']!r} but expected {vuln_class!r}")

    evidence = record.get("evidence")
    if evidence:
        evidence_path = Path(str(evidence))
        if not evidence_path.is_absolute():
            evidence_path = root / evidence_path
        if not evidence_path.exists():
            issues.append(f"coverage JSON cites missing evidence file: {evidence}")
        elif evidence_path.stat().st_size == 0:
            issues.append(f"coverage JSON cites empty evidence file: {evidence}")
    else:
        issues.append("coverage JSON lacks 'evidence' path")

    if vuln_class in SURFACE_DRIVEN_CLASSES:
        if record.get("kind") not in {None, "surface-driven"}:
            issues.append(
                f"surface-driven class JSON has kind={record.get('kind')!r}, expected surface-driven"
            )
        status = (record.get("surface_status") or "").strip()
        if not status:
            issues.append("surface-driven coverage JSON missing 'surface_status'")
        elif not (
            status.startswith("no-signal")
            or status.startswith("signal:")
            or status.startswith("candidate-dispatched:")
        ):
            issues.append(
                "surface_status must start with no-signal, signal:<details>, "
                "or candidate-dispatched:<hunter>"
            )
        elif status.startswith("signal:") and "candidate-dispatched" not in status and "candidate-dispatched" not in (record.get("dispatch") or ""):
            issues.append("surface_status records 'signal:' but no escalation candidate-dispatched recorded")
        return issues

    if record.get("kind") not in {None, "dispatched"}:
        issues.append(f"dispatched class JSON has kind={record.get('kind')!r}, expected dispatched")

    if (record.get("hard_blocker") or "").strip():
        return issues  # hard policy/scope/WAF blocker — accepted as-is

    attempts = int(record.get("attempts") or 0)
    if attempts < 25:
        issues.append(f"only {attempts} attempts recorded; Depth Engine floor is 25")

    combos_remaining = int(record.get("combos_remaining") or 0)
    combos_tested = int(record.get("combos_tested") or 0)
    if combos_remaining > max(5, combos_tested // 2):
        issues.append(f"too much matrix unexplored: combos_remaining={combos_remaining}")

    if int(record.get("encoding_steps") or 0) < 3:
        issues.append("encoding ladder depth too shallow (<3)")

    if not bool(record.get("differential_evidence")):
        issues.append("missing differential_evidence")

    blocker = (record.get("blocker") or "").strip()
    if len(blocker) < 20:
        issues.append("blocker is generic; describe the technical reason in >= 20 chars")

    return issues


def _artifact_path(surface_dirs: list[Path], names: tuple[str, ...]) -> Path | None:
    for surface_dir in surface_dirs:
        for name in names:
            path = surface_dir / name
            if path.exists() and path.stat().st_size > 0:
                return path
    return None


def _completion_marker(surface_dirs: list[Path]) -> Path | None:
    for surface_dir in surface_dirs:
        path = surface_dir / COMPLETION_MARKER_NAME
        if path.exists():
            return path
    return None


def _check_completion_marker(
    surface_dirs: list[Path],
    required_artifacts: list[tuple[str, str, Path]],
) -> str | None:
    marker = _completion_marker(surface_dirs)
    if marker is None:
        return (
            f"surface .complete marker missing in {surface_dirs[0]}; emit "
            "`date -u +%Y-%m-%dT%H:%M:%SZ > evidence/<host>/surface/.complete` "
            "after probes A-I succeed on this host"
        )
    try:
        marker_mtime = marker.stat().st_mtime
    except OSError as exc:
        return f"surface .complete marker unreadable: {exc}"
    newer: list[str] = []
    for probe_id, _name, artifact_path in required_artifacts:
        try:
            if artifact_path.stat().st_mtime > marker_mtime + 1:
                newer.append(f"probe {probe_id} ({artifact_path.name})")
        except OSError:
            continue
    if newer:
        return (
            "surface .complete marker is older than artifact(s) "
            + ", ".join(newer)
            + "; re-emit the marker after the latest probe finishes"
        )
    return None


def _read_first_artifact(surface_dirs: list[Path], names: tuple[str, ...]) -> str:
    path = _artifact_path(surface_dirs, names)
    return _read_text(path) if path else ""


def _surface_summary(surface_dirs: list[Path]) -> dict[str, object]:
    discovery = _read_first_artifact(surface_dirs, ("discovery.txt",))
    method_matrix = _read_first_artifact(surface_dirs, ("method-matrix.txt", "methods.txt"))

    non404: list[str] = []
    for line in discovery.splitlines():
        match = STATUS_LINE_RE.search(line.strip())
        if not match:
            continue
        status = int(match.group("status"))
        if status in {200, 201, 204, 301, 302, 303, 307, 308, 401, 403}:
            non404.append(match.group("path"))

    write_surface = False
    method_anomalies: list[str] = []
    for line in method_matrix.splitlines():
        match = METHOD_LINE_RE.search(line.strip())
        if not match:
            continue
        method = match.group("method").upper()
        status = int(match.group("status"))
        path = match.group("path")
        if method in {"POST", "PUT", "PATCH", "DELETE"} and status in {
            200,
            201,
            202,
            204,
            301,
            302,
            307,
            308,
            401,
            403,
        }:
            write_surface = True
            method_anomalies.append(f"{method} {path} {status}")

    return {
        "non404": non404,
        "write_surface": write_surface,
        "method_anomalies": method_anomalies,
    }


def _parse_attempts(text: str) -> int:
    total = 0
    for match in ATTEMPT_RE.finditer(text):
        total += int(match.group("n1") or match.group("n2") or 0)
    return total


def _remaining_counts(text: str) -> list[int]:
    return [int(match.group("n")) for match in REMAINING_RE.finditer(text)]


def _coverage_lines(content: str, vuln_class: str) -> list[str]:
    pattern = re.compile(rf"^.*\bcoverage-{re.escape(vuln_class)}\b.*$", re.MULTILINE)
    return pattern.findall(content)


def _not_applicable_lines(content: str, vuln_class: str) -> list[str]:
    pattern = re.compile(rf"^.*\bnot-applicable\s*:\s*{re.escape(vuln_class)}\b.*$", re.MULTILINE | re.IGNORECASE)
    return pattern.findall(content)


def _validate_not_applicable(line: str, vuln_class: str, surface: dict[str, object]) -> str:
    lower = line.lower()
    generic_markers = ("obvious", "not relevant", "n/a", "none", "no vuln", "no findings")
    has_surface_evidence = any(
        marker in lower
        for marker in (
            "surface",
            "probe",
            "discovery",
            "method-matrix",
            "cors-matrix",
            "h2-desync",
            "takeover",
            "artifact",
            "evidence/",
        )
    )
    if len(line) < 80 or not has_surface_evidence or any(marker == lower.strip() for marker in generic_markers):
        return "not-applicable entry is generic; cite concrete surface-probe evidence and artifact/status data"

    if vuln_class in {"xss-stored", "csrf", "race-condition", "business-logic", "file-upload"}:
        if surface.get("write_surface") and "no write" in lower:
            examples = ", ".join(surface.get("method_anomalies", [])[:3])
            return f"claims no write surface, but method matrix found write-capable routes: {examples}"
    return ""


def _validate_coverage(vuln_class: str, lines: list[str]) -> list[str]:
    issues: list[str] = []
    joined = "\n".join(lines)
    lower = joined.lower()

    if vuln_class in SURFACE_DRIVEN_CLASSES:
        if not any(token in lower for token in ("no-signal", "signal:", "candidate-dispatched")):
            issues.append("surface-driven coverage must be no-signal, signal:<details>, or candidate-dispatched:<hunter>")
        if "signal:" in lower and "candidate-dispatched" not in lower:
            issues.append("surface probe recorded signal but no escalation dispatch is recorded")
        return issues

    attempts = _parse_attempts(joined)
    if attempts < 25:
        issues.append(f"only {attempts} attempts recorded; Depth Engine floor is 25 with explicit attempts:N")

    required_markers = ("variants_tried", "dimensions_covered", "exact_blocker")
    missing = [marker for marker in required_markers if marker not in lower]
    if missing and any(token in lower for token in ("exhaust", "no-signal", "no signal", "not vulnerable", "blocked")):
        issues.append("coverage/exhaustion ledger missing " + ", ".join(missing))

    remaining = _remaining_counts(joined)
    if any(value > 0 for value in remaining):
        issues.append(f"coverage still has remaining combinations: {remaining}")

    if "differential" not in lower:
        issues.append("coverage lacks differential-evidence marker")

    return issues


def _target_file_for(root: Path, brain_meta: dict[str, dict[str, str]], target: str) -> tuple[Path | None, str, str]:
    if target in brain_meta:
        meta = brain_meta[target]
        return Path(meta["path"]), meta.get("content", ""), meta.get("slug", "")

    slug = slugify_target(target)
    path = root / ".claude" / "agent-memory-local" / "brain" / "targets" / f"{slug}.md"
    if path.exists():
        return path, _read_text(path), slug
    return None, "", slug


def _has_cf_signal(target: str, target_content: str, root: Path) -> bool:
    haystacks = [target_content]
    for path in (
        root / ".claude" / "agent-memory-local" / "brain" / "techniques" / "waf-bypasses.md",
        root / "evidence" / target / "surface" / "discovery.txt",
    ):
        if path.exists():
            haystacks.append(_read_text(path))
    target_l = target.lower()
    for text in haystacks:
        lower = text.lower()
        if target_l in lower and any(marker in lower for marker in ("cloudflare", "cf-ray", "cf-cache-status")):
            return True
    return False


def _parse_run_env(root: Path) -> dict[str, str]:
    env_path = root / ".autopilot-run.env"
    env: dict[str, str] = {}
    if not env_path.exists():
        return env
    for raw_line in _read_text(env_path).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :]
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        try:
            value = shlex.split(value, posix=True)[0] if value.strip() else ""
        except ValueError:
            value = value.strip().strip("'\"")
        env[key.strip()] = value
    return env


def _epoch_from_iso(value: str) -> int:
    if not value:
        return 0
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return 0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def _count_subagents(root: Path, start_epoch: int) -> int:
    cost_path = root / "cost-tracking.json"
    if not cost_path.exists():
        return 0
    try:
        data = json.loads(_read_text(cost_path))
    except json.JSONDecodeError:
        return 0
    count = 0
    for entry in data.get("entries", []):
        if not isinstance(entry, dict) or entry.get("event") != "agent_complete":
            continue
        ts = _epoch_from_iso(str(entry.get("ts", "")))
        if start_epoch and ts and ts < start_epoch:
            continue
        count += 1
    return count


def _bucket_minute(epoch_seconds: int) -> int:
    return epoch_seconds // 60


def _collect_active_timestamps(root: Path, start_epoch: int) -> list[int]:
    """Return epoch-seconds for actions that count as active work after start_epoch.

    Active work = something that proves an agent or hunter actually produced
    output, not pure wait time. This is what the active-work clock keys off.
    """
    timestamps: list[int] = []

    cost_path = root / "cost-tracking.json"
    if cost_path.exists():
        try:
            data = json.loads(_read_text(cost_path))
        except json.JSONDecodeError:
            data = {}
        for entry in data.get("entries", []) if isinstance(data, dict) else []:
            if not isinstance(entry, dict):
                continue
            ts = _epoch_from_iso(str(entry.get("ts", "")))
            if ts and (not start_epoch or ts >= start_epoch):
                timestamps.append(ts)

    journal_path = root / "journal.jsonl"
    if journal_path.exists():
        for raw_line in _read_text(journal_path).splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(entry, dict):
                continue
            ts = _epoch_from_iso(str(entry.get("ts", "")))
            if ts and (not start_epoch or ts >= start_epoch):
                timestamps.append(ts)

    coverage_root = root / "evidence"
    if coverage_root.exists():
        for path in coverage_root.glob("*/coverage/*.json"):
            try:
                record = json.loads(_read_text(path))
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            ts = _epoch_from_iso(str(record.get("created_at") or ""))
            if not ts:
                try:
                    ts = int(path.stat().st_mtime)
                except OSError:
                    ts = 0
            if ts and (not start_epoch or ts >= start_epoch):
                timestamps.append(ts)

    return timestamps


def _active_minute_buckets(root: Path, start_epoch: int) -> int:
    timestamps = _collect_active_timestamps(root, start_epoch)
    return len({_bucket_minute(ts) for ts in timestamps})


def _surface_unauth_writes(surface_dirs: list[Path]) -> list[str]:
    """Extract POST/PUT/PATCH/DELETE method-matrix entries with 2xx/3xx response.

    Each entry is the path (with method prefix stripped) so we can match it
    against brain markers and human descriptions interchangeably.
    """
    method_matrix = _read_first_artifact(surface_dirs, ("method-matrix.txt", "methods.txt"))
    paths: list[str] = []
    seen: set[str] = set()
    for line in method_matrix.splitlines():
        match = METHOD_LINE_RE.search(line.strip())
        if not match:
            continue
        method = match.group("method").upper()
        if method not in {"POST", "PUT", "PATCH", "DELETE"}:
            continue
        status = str(match.group("status"))
        if status not in UNAUTH_WRITE_SUCCESS_STATUSES:
            continue
        path = match.group("path").rstrip(":")
        if path not in seen:
            seen.add(path)
            paths.append(path)
    return paths


def _normalize_battery_path(value: str) -> str:
    cleaned = value.strip().strip(",;:")
    return cleaned.split()[0] if cleaned else cleaned


def _validate_unauth_battery(
    target: str,
    content: str,
    surface_dirs: list[Path],
    root: Path,
    result: GateResult,
) -> None:
    surface_anomalies = _surface_unauth_writes(surface_dirs)
    brain_unauth_paths: list[str] = []
    for match in UNAUTH_WRITE_BRAIN_RE.finditer(content):
        brain_unauth_paths.append(_normalize_battery_path(match.group("path")))

    expected_paths = _dedupe([p for p in surface_anomalies + brain_unauth_paths if p])
    if not expected_paths:
        return

    battery_index: dict[str, list[str]] = {}
    for line in content.splitlines():
        for match in ADVERSARIAL_BATTERY_RE.finditer(line):
            key = _normalize_battery_path(match.group("path"))
            battery_index.setdefault(key, []).append(line)

    for path in expected_paths:
        entries = battery_index.get(path, [])
        if not entries:
            result.add(
                "missing-unauth-battery",
                (
                    f"unauth state-change at {path} has no adversarial-battery follow-up; "
                    "record `adversarial-battery:<path> attempts:>=10 mass-assignment:done "
                    "payload-fields:done id-collision:done race:done chain-anchors:done "
                    "evidence:<file>` after running the battery"
                ),
                target,
            )
            continue

        joined = "\n".join(entries).lower()
        attempts = _parse_attempts(joined)
        if attempts < UNAUTH_BATTERY_MIN_ATTEMPTS:
            result.add(
                "shallow-unauth-battery",
                f"adversarial-battery:{path} only {attempts} attempts; floor is {UNAUTH_BATTERY_MIN_ATTEMPTS}",
                target,
            )

        missing_dim = [dim for dim in UNAUTH_BATTERY_REQUIRED_DIMENSIONS if dim not in joined]
        if missing_dim:
            result.add(
                "shallow-unauth-battery",
                f"adversarial-battery:{path} missing dimension(s): " + ", ".join(missing_dim),
                target,
            )

        evidence_match = EVIDENCE_PATH_RE.search("\n".join(entries))
        if not evidence_match:
            result.add(
                "missing-battery-evidence",
                f"adversarial-battery:{path} lacks evidence:<file> reference",
                target,
            )
            continue
        evidence_path = Path(evidence_match.group("path"))
        if not evidence_path.is_absolute():
            evidence_path = root / evidence_path
        if not evidence_path.exists():
            result.add(
                "missing-battery-evidence",
                f"adversarial-battery:{path} evidence file does not exist: {evidence_match.group('path')}",
                target,
            )
        elif evidence_path.stat().st_size == 0:
            result.add(
                "missing-battery-evidence",
                f"adversarial-battery:{path} evidence file is empty: {evidence_match.group('path')}",
                target,
            )


def _scope_mobile_packages(root: Path) -> list[str]:
    """Return mobile package identifiers from scope.yaml (best-effort, no PyYAML dep).

    We deliberately keep this parser tolerant — scope.yaml syntax varies and the
    gate just needs to know whether the program lists at least one mobile asset.
    """
    scope_path = root / "scope.yaml"
    if not scope_path.exists():
        scope_path = root / "scope.yaml.example"
        if not scope_path.exists():
            return []

    text = _read_text(scope_path).lower()
    if not any(keyword in text for keyword in MOBILE_ASSET_KEYWORDS):
        return []

    packages: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if "type" in stripped and any(keyword in stripped for keyword in MOBILE_ASSET_KEYWORDS):
            # next-line asset detection is fragile; instead we hoist any quoted
            # `<asset>: <name>` value seen on the same line
            match = re.search(r"asset\s*:\s*['\"]?([A-Za-z0-9._-]+)", stripped)
            if match:
                packages.append(match.group(1))
        if stripped.startswith("package") or "android_package" in stripped or "ios_bundle" in stripped:
            match = re.search(r"['\"]([A-Za-z0-9._-]+)['\"]", stripped)
            if match:
                packages.append(match.group(1))
    return _dedupe(packages) or ["mobile"]


def _all_brain_content(brain: dict[str, dict[str, str]]) -> str:
    return "\n".join(meta.get("content", "") for meta in brain.values())


def _recon_skip_clauses(brain_text: str) -> dict[str, str]:
    skips: dict[str, str] = {}
    for match in RECON_SKIP_RE.finditer(brain_text):
        skips[match.group("artifact").lower()] = match.group("clause")
    return skips


def _validate_cross_region_inference(target: str, content: str, result: GateResult) -> None:
    for pattern in CROSS_REGION_INFERENCE_RES:
        match = pattern.search(content)
        if match:
            line = next(
                (
                    line.strip()
                    for line in content.splitlines()
                    if pattern.search(line)
                ),
                match.group(0),
            )
            result.add(
                "cross-region-inference",
                (
                    "brain entry uses cross-region inference (Rule 30 forbids treating one "
                    f"region's hardness as evidence about another): {line!r}. Run the "
                    "class/host coverage locally on this region or record a "
                    "policy-cited not-applicable."
                ),
                target,
            )
            break


def _host_prefix(host: str) -> str:
    parts = host.split(".")
    if not parts:
        return ""
    leftmost = parts[0]
    chunks = re.split(r"[-_]", leftmost)
    for chunk in chunks:
        if chunk and not chunk.isdigit():
            return chunk.lower()
    return leftmost.lower()


def _is_novel_host(host: str) -> bool:
    prefix = _host_prefix(host)
    return bool(prefix) and prefix not in GENERIC_HOST_PREFIXES


def _validate_recon_depth(root: Path, brain: dict[str, dict[str, str]], result: GateResult) -> None:
    skips = _recon_skip_clauses(_all_brain_content(brain))
    for artifact_id, candidates in RECON_DEPTH_ARTIFACTS:
        if artifact_id in skips:
            continue
        path: Path | None = None
        for candidate in candidates:
            current = root / candidate
            if current.exists() and current.stat().st_size > 0:
                path = current
                break
        if path is None:
            tried = " or ".join(candidates)
            result.add(
                "missing-recon-depth",
                f"recon-depth artifact missing: {tried}. Generate it or record "
                f"`recon-skip:{artifact_id} policy:<clause>` citing the policy clause that forbids it.",
            )

    packages = _scope_mobile_packages(root)
    if packages and "mobile" not in skips:
        endpoint_paths = list((root / "recon" / "mobile").glob("*.endpoints.txt"))
        if not any(p.stat().st_size > 0 for p in endpoint_paths):
            result.add(
                "missing-mobile-endpoints",
                "scope lists a mobile asset but recon/mobile/<package>.endpoints.txt is missing/empty. "
                "Decompile the APK/IPA and extract endpoints, or record "
                "`recon-skip:mobile policy:<clause>` citing the policy clause that forbids it.",
            )


def _validate_confirmed_findings(result: GateResult, target: str, content: str) -> None:
    for line in re.findall(r"^.*\[\s*CONFIRMED\s*\].*$", content, flags=re.MULTILINE | re.IGNORECASE):
        lower = line.lower()
        if "validator:pass" not in lower:
            result.add("finding-validator-missing", f"confirmed finding missing validator:PASS marker: {line}", target)
        if not re.search(r"devils?-advocate\s*:\s*(survives|downgrade)", lower):
            result.add("finding-da-missing", f"confirmed finding missing devil's-advocate marker: {line}", target)
        if re.search(r"(xss|prototype|postmessage|dom-clobber|css-injection)", lower):
            if not re.search(r"browser-verified\s*:\s*(confirmed|partial)", lower):
                result.add("finding-browser-missing", f"client-side confirmed finding missing browser verifier marker: {line}", target)


def evaluate_project(
    root: Path,
    target_arg: str = "",
    mode: str = "",
    min_wall_minutes: int = 90,
    min_subagents: int = 18,
    require_ranked_live: bool = True,
) -> GateResult:
    root = root.resolve()
    result = GateResult()

    brain_dir = root / ".claude" / "agent-memory-local" / "brain"
    brain = _brain_targets(brain_dir)
    live_hosts = _collect_live_hosts(root)
    ranked = _collect_ranked_targets(root, brain)

    env = _parse_run_env(root)
    mode = (mode or env.get("AUTOPILOT_MODE", "")).strip().lower()
    target_seed = normalize_target(target_arg or env.get("AUTOPILOT_TARGET", ""))
    if target_seed and target_seed not in ranked and target_seed in brain:
        ranked[target_seed] = brain[target_seed].get("priority") or "p1"

    result.live_hosts = live_hosts
    result.ranked_targets = ranked

    if require_ranked_live and live_hosts:
        unranked = [host for host in live_hosts if host not in ranked]
        for host in unranked:
            result.add(
                "unranked-live-host",
                "live host is not P1/P2/Kill ranked, so completion would be blind to it",
                host,
            )

    for host in live_hosts:
        if not _is_novel_host(host):
            continue
        bucket = ranked.get(host)
        if bucket and bucket != "p1":
            result.add(
                "novel-host-not-p1",
                (
                    f"host prefix {_host_prefix(host)!r} is not in the generic taxonomy "
                    "and likely represents a unique service code-path; promote to P1 or "
                    "justify the demotion in the ranking artifact"
                ),
                host,
            )

    p1_targets = [target for target, bucket in ranked.items() if bucket == "p1"]
    if not p1_targets:
        # Fail closed: in the absence of a ranker output, brain target files are
        # the only available target set. If live hosts exist, the unranked check
        # above already explains why completion is blocked.
        p1_targets = list(brain)
    if target_seed and not p1_targets:
        p1_targets = [target_seed]
    result.p1_targets = _dedupe(p1_targets)

    if not result.p1_targets:
        result.add("no-targets", "no P1 targets or brain target files found")
        return result

    for target in result.p1_targets:
        target_file, content, slug = _target_file_for(root, brain, target)
        if target_file is None or not content:
            result.add("missing-brain-target", "P1 target has no brain target file; create it before hunting", target)
            continue

        surface_dirs = _evidence_surface_dirs(root, target, slug)
        present_artifacts: list[tuple[str, str, Path]] = []
        for probe_id, probe_name, artifact_names in SURFACE_ARTIFACTS:
            artifact_path = _artifact_path(surface_dirs, artifact_names)
            if artifact_path is None:
                names = " or ".join(artifact_names)
                result.add(
                    "missing-surface-artifact",
                    f"surface probe {probe_id} ({probe_name}) artifact missing or empty: {names}",
                    target,
                )
            else:
                present_artifacts.append((probe_id, probe_name, artifact_path))
        if _has_cf_signal(target, content, root):
            cf_path = _artifact_path(surface_dirs, CF_ARTIFACT[2])
            if cf_path is None:
                result.add(
                    "missing-surface-artifact",
                    f"Cloudflare signal present but surface probe {CF_ARTIFACT[0]} artifact missing: {CF_ARTIFACT[2][0]}",
                    target,
                )
            else:
                present_artifacts.append((CF_ARTIFACT[0], CF_ARTIFACT[1], cf_path))

        completion_issue = _check_completion_marker(surface_dirs, present_artifacts)
        if completion_issue:
            result.add("surface-not-complete", completion_issue, target)

        surface = _surface_summary(surface_dirs)
        if not surface.get("non404") and _artifact_path(surface_dirs, ("discovery.txt",)) is not None:
            result.add(
                "empty-discovery-surface",
                "discovery artifact contains no 200/30x/401/403 attack surface; verify the probe reached the host",
                target,
            )

        coverage_dirs = _evidence_coverage_dirs(root, target, slug)

        for vuln_class in REQUIRED_CLASSES:
            json_record, json_path = _load_coverage_json(coverage_dirs, vuln_class)
            if json_record is None and json_path is not None:
                result.add(
                    "shallow-coverage",
                    f"{vuln_class}: coverage JSON at {json_path} is not valid JSON",
                    target,
                )
                continue
            if json_record is not None:
                json_issues = _validate_coverage_json(vuln_class, json_record, root)
                for issue in json_issues:
                    result.add("shallow-coverage", f"{vuln_class}: {issue}", target)
                continue

            coverage = _coverage_lines(content, vuln_class)
            not_app = _not_applicable_lines(content, vuln_class)

            if coverage:
                for issue in _validate_coverage(vuln_class, coverage):
                    result.add("shallow-coverage", f"{vuln_class}: {issue}", target)
                continue

            if not_app:
                valid_na = False
                invalid_reasons: list[str] = []
                for line in not_app:
                    reason = _validate_not_applicable(line, vuln_class, surface)
                    if reason:
                        invalid_reasons.append(reason)
                    else:
                        valid_na = True
                if not valid_na:
                    reason = "; ".join(_dedupe(invalid_reasons)) or "not-applicable entry is invalid"
                    result.add("invalid-not-applicable", f"{vuln_class}: {reason}", target)
                continue

            result.add(
                "missing-class-coverage",
                f"{vuln_class} never dispatched and has no valid not-applicable record",
                target,
            )

        forbidden_re = re.compile(
            r"EXHAUSTED.*(" + "|".join(re.escape(item) for item in FORBIDDEN_SUBSTITUTES) + r")",
            flags=re.IGNORECASE,
        )
        for line in forbidden_re.findall(content):
            result.add("forbidden-substitute", f"exhaustion claimed through auxiliary agent: {line}", target)

        _validate_unauth_battery(target, content, surface_dirs, root, result)

        _validate_cross_region_inference(target, content, result)

        _validate_confirmed_findings(result, target, content)

    _validate_recon_depth(root, brain, result)

    pending = root / ".claude" / "agent-memory-local" / "chain-pending.md"
    if pending.exists() and pending.stat().st_size > 0:
        pending_text = _read_text(pending)
        if re.search(r"^\s*[A-Za-z0-9]", pending_text, flags=re.MULTILINE):
            result.add("chain-pending", "chain-pending.md is non-empty; feeder findings still need chain resolution")

    if mode == "autonomous":
        now = int(datetime.now(tz=timezone.utc).timestamp())
        try:
            start_epoch = int(env.get("RUN_START_EPOCH", "0") or 0)
        except ValueError:
            start_epoch = 0
        if not start_epoch:
            result.add("missing-run-start", ".autopilot-run.env lacks RUN_START_EPOCH for autonomous wall-clock gate")
            start_epoch = now

        # Active-work clock — primary floor. Counts distinct minute buckets in
        # which an agent finished, a journal entry landed, or a structured
        # coverage record was created. Pure sleep cannot satisfy this; idle
        # waiting between dispatches is also insufficient.
        active_floor = len(result.p1_targets) * min_wall_minutes
        active_buckets = _active_minute_buckets(root, start_epoch)
        if active_buckets < active_floor:
            result.add(
                "active-work-floor",
                f"only {active_buckets} active minute-bucket(s) recorded since RUN_START_EPOCH; floor is "
                f"{active_floor} ({len(result.p1_targets)} P1 targets x {min_wall_minutes}). "
                "An active bucket needs a SubagentStop, journal action, or coverage_record.py write — "
                "wall-clock alone does not count.",
            )

        # Wall-clock kept as lower-priority diagnostic; it can flag a run that
        # is somehow long but inactive (or vice versa) without being the
        # primary completion floor.
        elapsed_min = max(0, (now - start_epoch) // 60)
        floor_min = len(result.p1_targets) * min_wall_minutes
        if elapsed_min < floor_min:
            result.add(
                "wall-clock-floor",
                f"only {elapsed_min} min elapsed; floor is {floor_min} min ({len(result.p1_targets)} P1 targets x {min_wall_minutes})",
            )

        subagents = _count_subagents(root, start_epoch)
        if subagents < min_subagents:
            result.add("subagent-floor", f"only {subagents} subagent completions recorded; floor is {min_subagents}")

    return result


def print_result(result: GateResult) -> None:
    if result.ok:
        targets = ", ".join(result.p1_targets)
        print(f"AUTOPILOT GATE PASS: {len(result.p1_targets)} P1 target(s): {targets}")
        return

    print("AUTOPILOT NOT COMPLETE")
    print(f"P1 targets considered: {', '.join(result.p1_targets) if result.p1_targets else '(none)'}")
    print(f"Live hosts discovered: {', '.join(result.live_hosts) if result.live_hosts else '(none)'}")
    print("")
    for issue in result.issues:
        print(issue.format())
    print("")
    print("Return to HUNT LOOP for the failing target/class. Do not print a completion summary.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Hard pre-completion gate for /autopilot")
    parser.add_argument("--root", type=Path, default=Path("."), help="Engagement workspace root")
    parser.add_argument("--target", default="", help="Original /autopilot target argument")
    parser.add_argument("--mode", choices=["", "interactive", "autonomous"], default="", help="Autopilot mode")
    parser.add_argument("--min-wall-minutes", type=int, default=90)
    parser.add_argument("--min-subagents", type=int, default=18)
    parser.add_argument(
        "--allow-unranked-live",
        action="store_true",
        help="Do not fail on live hosts missing P1/P2/Kill classification",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = evaluate_project(
        root=args.root,
        target_arg=args.target,
        mode=args.mode,
        min_wall_minutes=args.min_wall_minutes,
        min_subagents=args.min_subagents,
        require_ranked_live=not args.allow_unranked_live,
    )
    print_result(result)
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
