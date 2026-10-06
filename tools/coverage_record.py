#!/usr/bin/env python3
"""Structured per-host/per-class coverage writer for /autopilot.

Why this exists
---------------
Hunters previously satisfied class coverage by writing arbitrary markdown
lines like ``coverage-idor: tested`` to the brain target file. The hard
gate then greps for the class name and accepts the line as proof. That
made the gate signature-driven instead of substance-driven and is the
exact failure mode that produced the ``prod-*.nu.com.co`` exhaustion
incident.

This tool is the only sanctioned path to record final class coverage. It

* refuses to write a coverage file whose numbers do not satisfy
  :func:`tools.intel_engine.evaluate_exhaustion_gate`
* refuses to write if the cited evidence file is missing or empty
* writes ``evidence/<host>/coverage/<class>.json`` with the schema
  :func:`tools.autopilot_gate._load_coverage_json` reads
* finally appends a ``coverage-<class>`` brain entry that points at the
  JSON file so the markdown ledger and JSON stay in sync

Surface-driven classes (cache-deception, header-injection, h2-desync,
method-confusion) use ``--surface-status`` instead of ``--attempts``
because the gate accepts ``no-signal`` / ``signal:`` /
``candidate-dispatched:`` for those classes.

Usage::

    uv run python3 tools/coverage_record.py \\
      --host prod-x.example.com --class idor \\
      --attempts 27 --variants 9 --combos-tested 12 --combos-remaining 0 \\
      --encoding-steps 4 --differential-evidence \\
      --blocker "401 before app routing on every discovered object route" \\
      --evidence evidence/prod-x.example.com/coverage/idor-attempts.jsonl

    uv run python3 tools/coverage_record.py \\
      --host prod-x.example.com --class cache-deception \\
      --surface-status no-signal \\
      --evidence evidence/prod-x.example.com/surface/cache-deception.txt
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from intel_engine import evaluate_exhaustion_gate  # noqa: E402

SURFACE_DRIVEN_CLASSES = {
    "cache-deception",
    "header-injection",
    "h2-desync",
    "method-confusion",
}

VALID_SURFACE_PREFIXES = ("no-signal", "signal:", "candidate-dispatched:")


def _utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _slugify_host(host: str) -> str:
    return host.replace("://", "-").replace("/", "-").replace(":", "-").strip("-")


def _coverage_path(root: Path, host: str, vuln_class: str) -> Path:
    return root / "evidence" / host / "coverage" / f"{vuln_class}.json"


def _validate_evidence(evidence: Path) -> str | None:
    if not evidence.exists():
        return f"evidence file does not exist: {evidence}"
    try:
        size = evidence.stat().st_size
    except OSError as exc:
        return f"evidence file unreadable ({exc})"
    if size == 0:
        return f"evidence file is empty: {evidence}"
    return None


def _build_record_dispatched(args: argparse.Namespace) -> tuple[dict, str | None]:
    ok, reason = evaluate_exhaustion_gate(
        attempts=args.attempts,
        combos_tested=args.combos_tested,
        combos_remaining=args.combos_remaining,
        encoding_steps=args.encoding_steps,
        differential_evidence=args.differential_evidence,
        hard_blocker=args.hard_blocker or "",
    )
    if not ok:
        return {}, f"exhaustion gate refused: {reason}"

    blocker = (args.blocker or args.hard_blocker or "").strip()
    if len(blocker) < 20:
        return {}, "blocker is too generic; describe the technical reason in >= 20 chars"

    record = {
        "host": args.host,
        "class": args.vuln_class,
        "kind": "dispatched",
        "attempts": args.attempts,
        "variants": args.variants,
        "combos_tested": args.combos_tested,
        "combos_remaining": args.combos_remaining,
        "encoding_steps": args.encoding_steps,
        "differential_evidence": bool(args.differential_evidence),
        "blocker": blocker,
        "hard_blocker": (args.hard_blocker or "").strip(),
        "evidence": str(args.evidence),
        "created_at": _utc_now_iso(),
    }
    return record, None


def _build_record_surface(args: argparse.Namespace) -> tuple[dict, str | None]:
    status = (args.surface_status or "").strip()
    if not status:
        return {}, "--surface-status is required for surface-driven classes"
    if not any(status.startswith(prefix) for prefix in VALID_SURFACE_PREFIXES):
        return {}, (
            "--surface-status must start with no-signal, signal:<details>, "
            "or candidate-dispatched:<hunter>"
        )
    if status.startswith("signal:") and len(status) <= len("signal:"):
        return {}, "signal:<details> requires details after the colon"
    if status.startswith("candidate-dispatched:") and len(status) <= len("candidate-dispatched:"):
        return {}, "candidate-dispatched:<hunter> requires the hunter name"

    record = {
        "host": args.host,
        "class": args.vuln_class,
        "kind": "surface-driven",
        "surface_status": status,
        "evidence": str(args.evidence),
        "created_at": _utc_now_iso(),
    }
    return record, None


def _write_record(root: Path, record: dict) -> Path:
    target = _coverage_path(root, record["host"], record["class"])
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return target


def _append_brain(root: Path, record: dict, json_path: Path) -> None:
    if record["kind"] == "surface-driven":
        details = (
            f"{record['surface_status']} json:{json_path.relative_to(root)} "
            f"evidence:{record['evidence']}"
        )
    else:
        details = (
            f"attempts:{record['attempts']} variants_tried={record['variants']} "
            f"combos_tested:{record['combos_tested']} combos_remaining:{record['combos_remaining']} "
            f"encoding_steps:{record['encoding_steps']} differential-evidence "
            f"dimensions_covered=method/content-type/auth/encoding/parser-trick "
            f"exact_blocker=\"{record['blocker']}\" "
            f"json:{json_path.relative_to(root)} evidence:{record['evidence']}"
        )

    cmd = [
        "uv",
        "run",
        "python3",
        str(_TOOLS_DIR / "brain.py"),
        "record",
        record["host"],
        "recon",
        f"coverage-{record['class']}",
        details,
    ]
    completed = subprocess.run(cmd, cwd=root, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        sys.stderr.write(
            "warning: brain.py record exited "
            f"{completed.returncode} (json was still written): {completed.stderr.strip()}\n"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Write a validated per-host coverage record. Refuses if the "
        "exhaustion gate or evidence file checks fail.",
    )
    parser.add_argument("--host", required=True, help="Hostname tested (no scheme, no path)")
    parser.add_argument(
        "--class",
        dest="vuln_class",
        required=True,
        help="Canonical vuln class slug (idor, xss-reflected, ...)",
    )
    parser.add_argument(
        "--evidence",
        type=Path,
        required=True,
        help="Path to a non-empty evidence file produced by the hunter run",
    )
    parser.add_argument("--root", type=Path, default=Path("."), help="Engagement workspace root")

    dispatched = parser.add_argument_group("dispatched-class arguments (most classes)")
    dispatched.add_argument("--attempts", type=int, default=0)
    dispatched.add_argument("--variants", type=int, default=0)
    dispatched.add_argument("--combos-tested", type=int, default=0)
    dispatched.add_argument("--combos-remaining", type=int, default=0)
    dispatched.add_argument("--encoding-steps", type=int, default=0)
    dispatched.add_argument("--differential-evidence", action="store_true")
    dispatched.add_argument(
        "--blocker",
        default="",
        help="Concrete technical reason exhaustion was reached (non-generic, >= 20 chars)",
    )
    dispatched.add_argument(
        "--hard-blocker",
        default="",
        help="Optional hard policy/scope/WAF blocker, accepted by the exhaustion gate as-is",
    )

    surface = parser.add_argument_group("surface-driven-class arguments")
    surface.add_argument(
        "--surface-status",
        default="",
        help="One of no-signal | signal:<details> | candidate-dispatched:<hunter>",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.root.resolve()

    err = _validate_evidence(args.evidence.resolve() if args.evidence.is_absolute() else (root / args.evidence))
    if err:
        sys.stderr.write(f"refuse: {err}\n")
        return 1

    if args.vuln_class in SURFACE_DRIVEN_CLASSES:
        record, err = _build_record_surface(args)
    else:
        record, err = _build_record_dispatched(args)

    if err:
        sys.stderr.write(f"refuse: {err}\n")
        return 1

    json_path = _write_record(root, record)
    _append_brain(root, record, json_path)
    print(f"coverage written: {json_path.relative_to(root)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
