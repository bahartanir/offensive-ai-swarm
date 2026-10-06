from __future__ import annotations

import sys
from pathlib import Path

import pytest

SERVER_DIR = Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from models import (  # noqa: E402
    AssetType,
    Platform,
    ProgramScope,
    ScopeAsset,
    scope_to_yaml,
)

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]


def test_scope_to_yaml_escapes_quotes_and_backslashes() -> None:
    scope = ProgramScope(
        platform=Platform.BUGCROWD,
        program_handle="demo",
        program_name='Demo "Program"',
        program_url=r"https://example.com/path\with\slashes",
        in_scope=[
            ScopeAsset(
                asset='https://api.example.com/"v1"',
                asset_type=AssetType.URL,
                notes='line1 "quoted"\nline2',
            )
        ],
        out_of_scope=[
            ScopeAsset(
                asset=r'example.com\internal',
                asset_type=AssetType.OTHER,
                eligible=False,
                notes='avoid "test" area',
            )
        ],
    )

    yaml_text = scope_to_yaml(scope)

    assert 'program: "Demo \\"Program\\""' in yaml_text
    assert 'url: "https://example.com/path\\\\with\\\\slashes"' in yaml_text
    assert 'asset: "https://api.example.com/\\"v1\\""' in yaml_text
    assert 'notes: "line1 \\"quoted\\"\\nline2"' in yaml_text
    assert 'asset: "example.com\\\\internal"' in yaml_text
    assert 'reason: "avoid \\"test\\" area"' in yaml_text


@pytest.mark.skipif(yaml is None, reason="pyyaml required for round-trip verification")
@pytest.mark.parametrize(
    "hostile_asset",
    [
        'https://api.example.com/"quoted"',
        r"https://example.com/path\back\slashes",
        "https://example.com/path\nwith\nnewlines",
        "https://example.com/path\twith\ttabs",
        "https://example.com/path\rwith\rcarriage",
        "https://example.com/path\x00null",
        "https://example.com/こんにちは",
        "https://example.com/emoji-🔥",
        "https://example.com/very-long-" + ("a" * 500),
        "- leading-dash.example.com",
        "* wildcard.example.com",
        "# hash.example.com",
        "? question.example.com",
        "@ at.example.com",
        "! bang.example.com",
        "| pipe.example.com",
        ": colon-as-leader",
        "> gt.example.com",
        "{ brace.example.com",
        "[ bracket.example.com",
        "& amp.example.com",
    ],
)
def test_scope_yaml_round_trips_hostile_asset_names(hostile_asset: str) -> None:
    """Any asset name must survive scope_to_yaml → yaml.safe_load intact.

    This catches every class of YAML escape bypass at once: reserved
    indicators, control characters, unicode, long strings, and leading
    special chars. Before the pyyaml switch, escaping was incomplete
    (only \\, ", \\n) so any of these inputs could produce invalid YAML
    or a parsed value that differs from the input.
    """
    scope = ProgramScope(
        platform=Platform.HACKERONE,
        program_handle="demo",
        program_name="Demo",
        program_url="https://example.com",
        in_scope=[
            ScopeAsset(asset=hostile_asset, asset_type=AssetType.URL, notes=hostile_asset),
        ],
    )
    yaml_text = scope_to_yaml(scope)
    parsed = yaml.safe_load(yaml_text)
    assert parsed["in_scope"][0]["asset"] == hostile_asset
    assert parsed["in_scope"][0]["notes"] == hostile_asset


@pytest.mark.skipif(yaml is None, reason="pyyaml required for round-trip verification")
def test_scope_yaml_round_trips_hostile_program_name() -> None:
    scope = ProgramScope(
        platform=Platform.HACKERONE,
        program_handle="demo",
        program_name='Program "with quotes" and\nnewlines\tand tabs',
        program_url="https://example.com",
    )
    parsed = yaml.safe_load(scope_to_yaml(scope))
    assert parsed["program"] == 'Program "with quotes" and\nnewlines\tand tabs'
