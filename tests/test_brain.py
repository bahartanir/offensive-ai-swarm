"""Tests for tools.brain record_result — status expansion + frontmatter fix."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

_spec = importlib.util.spec_from_file_location(
    "brain", REPO_ROOT / "tools" / "brain.py"
)
assert _spec and _spec.loader
brain = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(brain)


def _init_brain(tmp_path: Path) -> Path:
    root = tmp_path / "brain"
    brain.init_brain(root)
    return root


def test_record_accepts_autopilot_emitted_statuses(tmp_path):
    """Every status the autopilot/hunt skills emit must be accepted."""
    root = _init_brain(tmp_path)

    for status, technique, details in [
        ("recon", "coverage-idor", "80% matrix"),
        ("waf-map", "edge", "cf on app"),
        ("waf-bypass", "L2+L4", "partial bypass"),
        ("browser-rejected", "dom-xss", "no sink"),
        ("da-killed", "idor", "public data"),
        ("chain", "idor->ssrf", "next hop"),
        ("duplicate", "open-redirect", "already filed"),
        ("policy", "dos", "oos"),
    ]:
        brain.record_result(root, "app.example.com", status, technique, details)

    content = (root / "targets" / "app-example-com.md").read_text()
    assert "[RECON] coverage-idor" in content
    assert "[WAF-MAP] edge" in content
    assert "[WAF-BYPASS] L2+L4" in content
    assert "[BROWSER REJECTED] dom-xss" in content
    assert "[DA KILLED] idor" in content
    assert "[CHAIN] idor->ssrf" in content
    assert "[DUPLICATE] open-redirect" in content
    assert "[POLICY] dos" in content


def test_record_updates_last_updated_correctly(tmp_path):
    """Frontmatter last_updated refresh: stale → today, only first match."""
    root = _init_brain(tmp_path)
    target_file = brain.ensure_target_file(root, "api.example.com")

    content = target_file.read_text()
    # Corrupt the frontmatter date so we can verify refresh.
    stale = content.replace(
        f"last_updated: {brain.today()}",
        "last_updated: 2001-01-01",
        1,
    )
    # Inject a second "last_updated:" line inside the body to confirm only
    # the frontmatter line is touched (the old implementation would break here).
    stale += "\n- note: fake last_updated: 2010-01-01\n"
    target_file.write_text(stale)

    brain.record_result(root, "api.example.com", "confirmed", "idor", "cross-tenant read")

    refreshed = target_file.read_text()
    assert f"last_updated: {brain.today()}" in refreshed
    # Body line unchanged:
    assert "- note: fake last_updated: 2010-01-01" in refreshed
    assert "[CONFIRMED] idor" in refreshed


def test_record_rejects_unknown_status(tmp_path, capsys):
    """Invalid statuses must sys.exit(1), not crash or silently accept."""
    _init_brain(tmp_path)
    import pytest

    with pytest.raises(SystemExit) as exc:
        brain.record_result(tmp_path / "brain", "x.example.com", "bogus", "t", "d")
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "status must be one of" in err


def test_touch_last_updated_appends_when_missing(tmp_path):
    """If frontmatter lacks last_updated, the helper should add it once."""
    f = tmp_path / "target.md"
    f.write_text("---\ntarget: x\n---\nbody\n")
    brain._touch_last_updated(f)
    assert f"last_updated: {brain.today()}" in f.read_text()


def test_record_and_list_capabilities(tmp_path, capsys):
    root = _init_brain(tmp_path)
    brain.record_capability(
        brain_dir=root,
        target="api.example.com",
        capability="session token",
        source="idor-read",
        confidence=0.9,
        details="token leaked via user profile endpoint",
    )
    brain.record_capability(
        brain_dir=root,
        target="api.example.com",
        capability="authenticated actions",
        source="csrf token theft",
        confidence=0.8,
        details="csrf extracted with reflected xss",
        from_capability="session token",
    )
    graph = brain.load_capability_graph(root)
    assert "session token" in graph["nodes"]
    assert "authenticated actions" in graph["nodes"]
    assert graph["edges"], "expected transition edge from prior capability"

    brain.list_capabilities(root, "api.example.com")
    out = capsys.readouterr().out
    assert "session token" in out.lower()


def test_load_capability_graph_quarantines_corrupt_file(tmp_path, capsys):
    """A corrupt capability-graph.json must be preserved, not silently wiped.

    Before the fix, the loader's bare `except: pass` returned an empty graph,
    and the next `record_capability` call would overwrite the corrupt file
    with a single observation — erasing every prior attacker capability."""
    root = _init_brain(tmp_path)
    graph_file = root / "patterns" / "capability-graph.json"
    graph_file.parent.mkdir(parents=True, exist_ok=True)
    graph_file.write_text("{not valid json")

    graph = brain.load_capability_graph(root)
    assert graph == {"version": 1, "nodes": {}, "edges": []}
    preserved = list(graph_file.parent.glob("capability-graph.json.corrupt-*"))
    assert len(preserved) == 1, "corrupt graph must be preserved for recovery"
    err = capsys.readouterr().err
    assert "corrupt" in err.lower()


def test_record_capability_is_atomic(tmp_path):
    """After a successful save, the .tmp sibling must not linger."""
    root = _init_brain(tmp_path)
    brain.record_capability(
        brain_dir=root,
        target="t",
        capability="c",
        source="s",
        confidence=0.5,
    )
    graph_file = root / "patterns" / "capability-graph.json"
    assert graph_file.exists()
    assert not (graph_file.parent / "capability-graph.json.tmp").exists()


def test_record_capability_rejects_self_loop(tmp_path, capsys):
    """An edge from a capability to itself is meaningless and must not be recorded."""
    root = _init_brain(tmp_path)
    brain.record_capability(
        brain_dir=root,
        target="t",
        capability="js-execution",
        from_capability="js-execution",
        source="test",
    )
    graph = brain.load_capability_graph(root)
    # Node still recorded, but no self-loop edge.
    assert "js-execution" in graph["nodes"]
    assert not any(e["from"] == e["to"] for e in graph["edges"])
    err = capsys.readouterr().err
    assert "self-loop" in err.lower()


def test_record_capability_strips_newlines_in_log(tmp_path):
    """User-controlled capability/source must not corrupt the one-line-per-entry log."""
    root = _init_brain(tmp_path)
    brain.record_capability(
        brain_dir=root,
        target="t",
        capability="multi\nline\ncapability",
        source="s\nwith\nnewlines",
    )
    # Session log lives under sessions/<date>.md
    session_dir = root / "sessions"
    log_files = list(session_dir.glob("*.md"))
    assert log_files, "session log should exist"
    log_content = log_files[0].read_text()
    # Each session entry must remain on a single line; newlines in input must be scrubbed.
    capability_lines = [ln for ln in log_content.splitlines() if "Capability:" in ln]
    assert capability_lines
    for ln in capability_lines:
        assert "\n" not in ln
        assert "multi line capability" in ln or "multi\\nline" not in ln
