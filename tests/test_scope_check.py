"""Regression tests for scope_check placeholder handling.

The sync_program placeholder scope files are the single path by which
"platform API returned no scope" could previously be mistaken for
"scope is legitimately empty". scope_check must refuse every target
against a placeholder scope."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import scope_check  # noqa: E402


def test_load_scope_yaml_detects_placeholder_sentinel(tmp_path: Path) -> None:
    yaml_path = tmp_path / "scope.yaml"
    yaml_path.write_text(
        "scope_mode: placeholder\n"
        'program: "ghost"\n'
        'platform: fakeplatform\n'
        'url: ""\n'
        "in_scope: []\n"
        "out_of_scope: []\n"
    )
    scope = scope_check.load_scope_yaml(yaml_path)
    assert scope["placeholder"] is True


def test_check_scope_refuses_placeholder(tmp_path: Path) -> None:
    """Every target must be NO_SCOPE_FILE against a placeholder — never
    UNCERTAIN, IN_SCOPE, or OUT_OF_SCOPE. Incomplete scope is a hard stop."""
    yaml_path = tmp_path / "scope.yaml"
    yaml_path.write_text(
        "scope_mode: placeholder\n"
        'program: "ghost"\n'
        "in_scope: []\n"
        "out_of_scope: []\n"
    )
    scope = scope_check.load_scope_yaml(yaml_path)
    verdict = scope_check.check_scope("api.example.com", scope)
    assert verdict["status"] == "NO_SCOPE_FILE"
    assert "placeholder" in verdict["message"].lower()


def test_check_scope_respects_real_empty_scope(tmp_path: Path) -> None:
    """A real (non-placeholder) scope that happens to have empty lists must
    still return UNCERTAIN — the operator explicitly populated an empty
    scope and the sentinel is absent."""
    yaml_path = tmp_path / "scope.yaml"
    yaml_path.write_text(
        'program: "real"\n'
        "in_scope: []\n"
        "out_of_scope: []\n"
    )
    scope = scope_check.load_scope_yaml(yaml_path)
    assert not scope.get("placeholder")
    verdict = scope_check.check_scope("api.example.com", scope)
    assert verdict["status"] == "UNCERTAIN"
