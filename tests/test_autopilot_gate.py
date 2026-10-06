"""Regression tests for the hard /autopilot pre-completion gate."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import autopilot_gate  # noqa: E402


TARGET = "api.example.com"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _coverage_line(vuln_class: str) -> str:
    if vuln_class in autopilot_gate.SURFACE_DRIVEN_CLASSES:
        return f"- [RECON] coverage-{vuln_class} -- no-signal\n"
    return (
        f"- [RECON] coverage-{vuln_class} -- attempts:25 "
        "variants_tried=matrix dimensions_covered=method/content-type/auth/encoding "
        "exact_blocker=no-signal differential-evidence combos_remaining:0\n"
    )


def _complete_target_content(target: str = TARGET) -> str:
    coverage = "".join(_coverage_line(cls) for cls in autopilot_gate.REQUIRED_CLASSES)
    return f"""---
target: {target}
priority: p1
status: active
---
# {target}

{coverage}
"""


def _write_complete_surface(root: Path, target: str = TARGET) -> None:
    surface = root / "evidence" / target / "surface"
    _write(surface / "discovery.txt", "/ 200 10\napi/ 401 0\n")
    _write(surface / "method-matrix.txt", "GET /: 200 10\nPOST api/: 401 0\n")
    _write(surface / "cache-deception.txt", "/profile.css: cache-control: no-store\n")
    _write(surface / "header-injection.txt", "no reflected set-cookie/location\n")
    _write(surface / "cors-matrix.txt", "no access-control-allow-origin reflection\n")
    _write(surface / "h2-desync.txt", "HTTP/2 400 no leakage\n")
    _write(surface / "takeover.txt", "no dangling vendor pattern\n")
    _write(surface / "spa-routing.txt", "next=//evil.tld: 200 10\n")
    _write(surface / ".complete", "2026-05-06T00:00:00Z\n")


def _write_complete_workspace(root: Path, target: str = TARGET) -> None:
    _write(root / "recon" / "live-hosts.txt", f"https://{target}\n")
    _write(
        root / ".claude" / "agent-memory-local" / "brain" / "targets" / f"{autopilot_gate.slugify_target(target)}.md",
        _complete_target_content(target),
    )
    _write_complete_surface(root, target)
    _write_complete_recon_depth(root)


def _write_complete_recon_depth(root: Path) -> None:
    _write(root / "recon" / "dns-bruteforce.txt", "no extra subdomains discovered\n")
    _write(root / "recon" / "urlscan-cdx.json", '{"results":[]}\n')
    _write(root / "recon" / "github-code.json", '{"items":[]}\n')
    _write(root / "recon" / "public-archives.txt", "no archived URLs\n")


def test_gate_passes_complete_interactive_workspace(tmp_path: Path) -> None:
    _write_complete_workspace(tmp_path)

    result = autopilot_gate.evaluate_project(tmp_path, mode="interactive")

    assert result.ok, [issue.format() for issue in result.issues]


def test_gate_fails_when_live_host_was_never_ranked(tmp_path: Path) -> None:
    _write_complete_workspace(tmp_path, TARGET)
    _write(tmp_path / "recon" / "live-hosts.txt", f"https://{TARGET}\nhttps://forgotten.example.com\n")

    result = autopilot_gate.evaluate_project(tmp_path, mode="interactive")

    assert not result.ok
    assert any(issue.code == "unranked-live-host" and issue.target == "forgotten.example.com" for issue in result.issues)


def test_gate_fails_missing_full_surface_artifacts(tmp_path: Path) -> None:
    _write_complete_workspace(tmp_path)
    (tmp_path / "evidence" / TARGET / "surface" / "method-matrix.txt").unlink()

    result = autopilot_gate.evaluate_project(tmp_path, mode="interactive")

    assert not result.ok
    assert any("surface probe B" in issue.message for issue in result.issues)


def test_gate_fails_shallow_dispatched_class_coverage(tmp_path: Path) -> None:
    _write_complete_workspace(tmp_path)
    target_file = tmp_path / ".claude" / "agent-memory-local" / "brain" / "targets" / "api-example-com.md"
    target_file.write_text(
        _complete_target_content().replace(
            "coverage-idor -- attempts:25",
            "coverage-idor -- attempts:4",
        )
    )

    result = autopilot_gate.evaluate_project(tmp_path, mode="interactive")

    assert not result.ok
    assert any(issue.code == "shallow-coverage" and "idor" in issue.message for issue in result.issues)


def test_gate_fails_generic_not_applicable_record(tmp_path: Path) -> None:
    _write_complete_workspace(tmp_path)
    target_file = tmp_path / ".claude" / "agent-memory-local" / "brain" / "targets" / "api-example-com.md"
    target_file.write_text(
        _complete_target_content().replace(
            _coverage_line("ssrf"),
            "- [RECON] not-applicable: ssrf -- n/a\n",
        )
    )

    result = autopilot_gate.evaluate_project(tmp_path, mode="interactive")

    assert not result.ok
    assert any(issue.code == "invalid-not-applicable" and "ssrf" in issue.message for issue in result.issues)


def test_gate_fails_surface_signal_without_candidate_dispatch(tmp_path: Path) -> None:
    _write_complete_workspace(tmp_path)
    target_file = tmp_path / ".claude" / "agent-memory-local" / "brain" / "targets" / "api-example-com.md"
    target_file.write_text(
        _complete_target_content().replace(
            _coverage_line("cache-deception"),
            "- [RECON] coverage-cache-deception -- signal:cf-cache-HIT-on-/profile.css\n",
        )
    )

    result = autopilot_gate.evaluate_project(tmp_path, mode="interactive")

    assert not result.ok
    assert any(
        issue.code == "shallow-coverage" and "cache-deception" in issue.message
        for issue in result.issues
    )


def test_gate_enforces_autonomous_wall_clock_and_subagent_floors(tmp_path: Path) -> None:
    _write_complete_workspace(tmp_path)
    _write(tmp_path / ".autopilot-run.env", "RUN_START_EPOCH=1\nAUTOPILOT_MODE=autonomous\n")

    result = autopilot_gate.evaluate_project(
        tmp_path,
        mode="autonomous",
        min_wall_minutes=999999999,
        min_subagents=18,
    )

    assert not result.ok
    assert any(issue.code == "wall-clock-floor" for issue in result.issues)
    assert any(issue.code == "subagent-floor" for issue in result.issues)


# ---------------------------------------------------------------------------
# JSON coverage substance gate (Phase 1)
# ---------------------------------------------------------------------------


def _write_valid_coverage_json(root: Path, host: str, vuln_class: str) -> Path:
    evidence = root / "evidence" / host / "coverage" / f"{vuln_class}-attempts.jsonl"
    _write(evidence, '{"attempt": 1, "result": "401"}\n')
    record = {
        "host": host,
        "class": vuln_class,
        "kind": "dispatched",
        "attempts": 27,
        "variants": 9,
        "combos_tested": 12,
        "combos_remaining": 0,
        "encoding_steps": 4,
        "differential_evidence": True,
        "blocker": "401 before app routing on every discovered object route",
        "evidence": str(evidence.relative_to(root)),
        "created_at": "2026-05-06T00:00:00Z",
    }
    target = root / "evidence" / host / "coverage" / f"{vuln_class}.json"
    _write(target, json.dumps(record, indent=2) + "\n")
    return target


def test_gate_passes_with_valid_json_coverage(tmp_path: Path) -> None:
    _write_complete_workspace(tmp_path)
    _write_valid_coverage_json(tmp_path, TARGET, "idor")

    # Wipe the markdown coverage line for IDOR so the gate has to honor JSON.
    target_file = tmp_path / ".claude" / "agent-memory-local" / "brain" / "targets" / "api-example-com.md"
    content = target_file.read_text().replace(_coverage_line("idor"), "")
    target_file.write_text(content)

    result = autopilot_gate.evaluate_project(tmp_path, mode="interactive")

    assert result.ok, [issue.format() for issue in result.issues]


def test_gate_fails_when_json_coverage_attempts_too_low(tmp_path: Path) -> None:
    _write_complete_workspace(tmp_path)
    json_path = _write_valid_coverage_json(tmp_path, TARGET, "idor")
    record = json.loads(json_path.read_text())
    record["attempts"] = 4
    json_path.write_text(json.dumps(record, indent=2) + "\n")

    target_file = tmp_path / ".claude" / "agent-memory-local" / "brain" / "targets" / "api-example-com.md"
    content = target_file.read_text().replace(_coverage_line("idor"), "")
    target_file.write_text(content)

    result = autopilot_gate.evaluate_project(tmp_path, mode="interactive")

    assert not result.ok
    assert any(
        issue.code == "shallow-coverage"
        and "idor" in issue.message
        and "Depth Engine floor" in issue.message
        for issue in result.issues
    )


def test_gate_fails_when_json_coverage_evidence_missing(tmp_path: Path) -> None:
    _write_complete_workspace(tmp_path)
    json_path = _write_valid_coverage_json(tmp_path, TARGET, "idor")
    record = json.loads(json_path.read_text())
    (tmp_path / record["evidence"]).unlink()

    target_file = tmp_path / ".claude" / "agent-memory-local" / "brain" / "targets" / "api-example-com.md"
    content = target_file.read_text().replace(_coverage_line("idor"), "")
    target_file.write_text(content)

    result = autopilot_gate.evaluate_project(tmp_path, mode="interactive")

    assert not result.ok
    assert any(
        issue.code == "shallow-coverage"
        and "idor" in issue.message
        and "missing evidence" in issue.message
        for issue in result.issues
    )


# ---------------------------------------------------------------------------
# Per-host .complete marker (Phase 2)
# ---------------------------------------------------------------------------


def test_gate_fails_when_complete_marker_missing(tmp_path: Path) -> None:
    _write_complete_workspace(tmp_path)
    (tmp_path / "evidence" / TARGET / "surface" / ".complete").unlink()

    result = autopilot_gate.evaluate_project(tmp_path, mode="interactive")

    assert not result.ok
    assert any(issue.code == "surface-not-complete" for issue in result.issues)


def test_gate_fails_when_complete_marker_older_than_artifact(tmp_path: Path) -> None:
    _write_complete_workspace(tmp_path)
    surface = tmp_path / "evidence" / TARGET / "surface"
    # Backdate the marker
    old = time.time() - 3600
    os.utime(surface / ".complete", (old, old))
    # Touch one artifact to make it newer than the marker
    discovery = surface / "discovery.txt"
    now = time.time()
    os.utime(discovery, (now, now))

    result = autopilot_gate.evaluate_project(tmp_path, mode="interactive")

    assert not result.ok
    assert any(
        issue.code == "surface-not-complete" and "older than" in issue.message
        for issue in result.issues
    )


# ---------------------------------------------------------------------------
# Active-work clock (Phase 3)
# ---------------------------------------------------------------------------


def test_gate_fails_active_work_clock_when_only_sleep(tmp_path: Path) -> None:
    _write_complete_workspace(tmp_path)
    # Run started 91 minutes ago, but no journal/cost/coverage activity exists.
    start = int(time.time()) - 91 * 60
    _write(
        tmp_path / ".autopilot-run.env",
        f"RUN_START_EPOCH={start}\nAUTOPILOT_MODE=autonomous\n",
    )

    result = autopilot_gate.evaluate_project(
        tmp_path,
        mode="autonomous",
        min_wall_minutes=90,
        min_subagents=18,
    )

    assert not result.ok
    assert any(issue.code == "active-work-floor" for issue in result.issues)


def test_gate_passes_active_work_clock_with_distinct_minute_buckets(tmp_path: Path) -> None:
    _write_complete_workspace(tmp_path)
    start = int(time.time()) - 100 * 60
    _write(
        tmp_path / ".autopilot-run.env",
        f"RUN_START_EPOCH={start}\nAUTOPILOT_MODE=autonomous\n",
    )
    # Build cost-tracking entries — one per minute for 95 distinct minute buckets
    entries = []
    from datetime import datetime, timezone

    for minute_offset in range(95):
        ts = datetime.fromtimestamp(start + minute_offset * 60, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        entries.append({"ts": ts, "event": "agent_complete", "agent": "idor-hunter"})
    _write(tmp_path / "cost-tracking.json", json.dumps({"entries": entries}))

    result = autopilot_gate.evaluate_project(
        tmp_path,
        mode="autonomous",
        min_wall_minutes=90,
        min_subagents=18,
    )

    # Both wall-clock and active-work floors should be satisfied.
    assert not any(issue.code == "active-work-floor" for issue in result.issues), [
        i.format() for i in result.issues
    ]
    assert not any(issue.code == "wall-clock-floor" for issue in result.issues), [
        i.format() for i in result.issues
    ]


# ---------------------------------------------------------------------------
# Unauth state-change battery (Phase 4)
# ---------------------------------------------------------------------------


def test_gate_fails_when_unauth_write_has_no_battery(tmp_path: Path) -> None:
    _write_complete_workspace(tmp_path)
    surface = tmp_path / "evidence" / TARGET / "surface"
    # Method matrix records POST 200 — that's an unauth write surface
    _write(
        surface / "method-matrix.txt",
        "POST /api/save: 200 0\nGET /: 200 10\n",
    )
    # Re-touch .complete so it remains newer than artifacts
    now = time.time()
    os.utime(surface / ".complete", (now + 1, now + 1))

    result = autopilot_gate.evaluate_project(tmp_path, mode="interactive")

    assert not result.ok
    assert any(
        issue.code == "missing-unauth-battery" and "/api/save" in issue.message
        for issue in result.issues
    )


def test_gate_passes_when_unauth_write_has_full_battery(tmp_path: Path) -> None:
    _write_complete_workspace(tmp_path)
    surface = tmp_path / "evidence" / TARGET / "surface"
    _write(
        surface / "method-matrix.txt",
        "POST /api/save: 200 0\nGET /: 200 10\n",
    )
    now = time.time()
    os.utime(surface / ".complete", (now + 1, now + 1))

    battery_evidence = tmp_path / "evidence" / TARGET / "battery-api-save.jsonl"
    _write(battery_evidence, '{"attempt": 1}\n')

    target_file = tmp_path / ".claude" / "agent-memory-local" / "brain" / "targets" / "api-example-com.md"
    content = target_file.read_text() + (
        "\n- [RECON] adversarial-battery:/api/save -- attempts:11 mass-assignment:done "
        "payload-fields:done id-collision:done race:done chain-anchors:done "
        f"evidence:{battery_evidence.relative_to(tmp_path)}\n"
    )
    target_file.write_text(content)

    result = autopilot_gate.evaluate_project(tmp_path, mode="interactive")

    assert result.ok, [issue.format() for issue in result.issues]


def test_gate_fails_when_unauth_battery_too_shallow(tmp_path: Path) -> None:
    _write_complete_workspace(tmp_path)
    surface = tmp_path / "evidence" / TARGET / "surface"
    _write(
        surface / "method-matrix.txt",
        "POST /api/save: 200 0\nGET /: 200 10\n",
    )
    now = time.time()
    os.utime(surface / ".complete", (now + 1, now + 1))

    battery_evidence = tmp_path / "evidence" / TARGET / "battery-api-save.jsonl"
    _write(battery_evidence, '{"attempt": 1}\n')

    target_file = tmp_path / ".claude" / "agent-memory-local" / "brain" / "targets" / "api-example-com.md"
    content = target_file.read_text() + (
        "\n- [RECON] adversarial-battery:/api/save -- attempts:3 mass-assignment:done "
        f"evidence:{battery_evidence.relative_to(tmp_path)}\n"
    )
    target_file.write_text(content)

    result = autopilot_gate.evaluate_project(tmp_path, mode="interactive")

    assert not result.ok
    assert any(
        issue.code == "shallow-unauth-battery" and "attempts" in issue.message
        for issue in result.issues
    )


# ---------------------------------------------------------------------------
# Recon-depth gate (Phase 5)
# ---------------------------------------------------------------------------


def test_gate_fails_when_recon_depth_artifact_missing(tmp_path: Path) -> None:
    _write_complete_workspace(tmp_path)
    (tmp_path / "recon" / "dns-bruteforce.txt").unlink()

    result = autopilot_gate.evaluate_project(tmp_path, mode="interactive")

    assert not result.ok
    assert any(
        issue.code == "missing-recon-depth" and "dns-bruteforce" in issue.message
        for issue in result.issues
    )


def test_gate_passes_when_recon_skip_cites_policy_clause(tmp_path: Path) -> None:
    _write_complete_workspace(tmp_path)
    (tmp_path / "recon" / "dns-bruteforce.txt").unlink()

    target_file = tmp_path / ".claude" / "agent-memory-local" / "brain" / "targets" / "api-example-com.md"
    content = target_file.read_text() + (
        "\n- [RECON] recon-skip:dns-bruteforce policy:section-3.2 -- automated brute-force forbidden\n"
    )
    target_file.write_text(content)

    result = autopilot_gate.evaluate_project(tmp_path, mode="interactive")

    assert result.ok, [issue.format() for issue in result.issues]


def test_gate_fails_when_mobile_scoped_but_no_endpoints(tmp_path: Path) -> None:
    _write_complete_workspace(tmp_path)
    _write(
        tmp_path / "scope.yaml",
        "in_scope:\n  - asset: 'com.example.android'\n    type: mobile_app\n",
    )

    result = autopilot_gate.evaluate_project(tmp_path, mode="interactive")

    assert not result.ok
    assert any(issue.code == "missing-mobile-endpoints" for issue in result.issues)


# ---------------------------------------------------------------------------
# Cross-region inference (Phase 6)
# ---------------------------------------------------------------------------


def test_gate_fails_on_cross_region_inference_phrase(tmp_path: Path) -> None:
    _write_complete_workspace(tmp_path)
    target_file = tmp_path / ".claude" / "agent-memory-local" / "brain" / "targets" / "api-example-com.md"
    content = target_file.read_text() + (
        "\n- [INFO] same-code-as-BR — assumed equivalent hardness, skipping CO probes\n"
    )
    target_file.write_text(content)

    result = autopilot_gate.evaluate_project(tmp_path, mode="interactive")

    assert not result.ok
    assert any(issue.code == "cross-region-inference" for issue in result.issues)


# ---------------------------------------------------------------------------
# Novel hostname trigger (Phase 7)
# ---------------------------------------------------------------------------


def test_gate_fails_when_novel_host_demoted_below_p1(tmp_path: Path) -> None:
    _write_complete_workspace(tmp_path)
    # Add a novel-named live host ranked P2
    _write(
        tmp_path / "recon" / "live-hosts.txt",
        f"https://{TARGET}\nhttps://prod-s0-milli-vanilli.example.com\n",
    )
    _write(
        tmp_path / "ATTACK_SURFACE_RANKING.md",
        "P1 api.example.com\nP2 prod-s0-milli-vanilli.example.com\n",
    )

    result = autopilot_gate.evaluate_project(tmp_path, mode="interactive")

    assert not result.ok
    assert any(
        issue.code == "novel-host-not-p1"
        and issue.target == "prod-s0-milli-vanilli.example.com"
        for issue in result.issues
    )


def test_gate_allows_generic_host_demoted_below_p1(tmp_path: Path) -> None:
    _write_complete_workspace(tmp_path)
    # Add a generic-named live host ranked P2 — this should NOT trip the novel-host gate
    _write(
        tmp_path / "recon" / "live-hosts.txt",
        f"https://{TARGET}\nhttps://cdn.example.com\n",
    )
    _write(
        tmp_path / "ATTACK_SURFACE_RANKING.md",
        "P1 api.example.com\nP2 cdn.example.com\n",
    )

    result = autopilot_gate.evaluate_project(tmp_path, mode="interactive")

    assert not any(issue.code == "novel-host-not-p1" for issue in result.issues), [
        i.format() for i in result.issues
    ]
