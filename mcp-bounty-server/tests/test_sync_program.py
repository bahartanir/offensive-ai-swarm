"""Regression tests for sync_program output guarantees."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path


def _install_mcp_stub() -> None:
    if "mcp" in sys.modules:
        return
    fake_mcp = types.ModuleType("mcp")
    fake_mcp.server = types.ModuleType("mcp.server")
    fake_mcp.server.stdio = types.ModuleType("mcp.server.stdio")
    fake_mcp.types = types.ModuleType("mcp.types")

    class _Server:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def list_tools(self):
            return lambda f: f

        def call_tool(self):
            return lambda f: f

        def create_initialization_options(self):
            return {}

    class _Dummy:
        def __init__(self, **_kwargs) -> None:
            for key, value in _kwargs.items():
                setattr(self, key, value)

    fake_mcp.server.Server = _Server
    fake_mcp.server.stdio.stdio_server = lambda: None
    fake_mcp.types.Tool = _Dummy
    fake_mcp.types.TextContent = _Dummy

    sys.modules["mcp"] = fake_mcp
    sys.modules["mcp.server"] = fake_mcp.server
    sys.modules["mcp.server.stdio"] = fake_mcp.server.stdio
    sys.modules["mcp.types"] = fake_mcp.types


def _load_server_module():
    _install_mcp_stub()
    server_dir = Path(__file__).resolve().parents[1]
    if str(server_dir) not in sys.path:
        sys.path.insert(0, str(server_dir))
    server_py = server_dir / "server.py"
    spec = importlib.util.spec_from_file_location("mcp_bounty_server_test_module", server_py)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Make this test resilient to MCP stubs installed by other test modules
    # (e.g. mcp-writeup-server tests) that define a bare TextContent class
    # without a `text` attribute.
    class _TextContent:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    module.TextContent = _TextContent
    return module


def _stub_provider(module, *, scope=None, policy=None, entries=None):
    class _Provider:
        platform_name = "FakePlatform"
        platform_id = "fakeplatform"
        is_configured = True

        async def get_scope(self, _program):
            return scope

        async def get_policy(self, _program):
            return policy

        async def search_hacktivity(self, _program, query="", limit=50):
            assert query in ("",)
            return (entries or [])[:limit]

    return _Provider()


def _set_provider(module, provider):
    module.registry = {"fakeplatform": provider}


def _content_text(result):
    return result[0].text


def test_sync_program_writes_scope_md_and_policy_with_real_scope(tmp_path):
    module = _load_server_module()
    models = __import__("models")

    scope = models.ProgramScope(
        platform=models.Platform.BUGCROWD,
        program_handle="acme",
        program_name='ACME "Corp"',
        program_url="https://example.com/program",
        in_scope=[
            models.ScopeAsset(
                asset='https://api.example.com/v1/"quotes"',
                asset_type=models.AssetType.URL,
                notes='path has "quotes" and \\backslashes\\',
            )
        ],
        out_of_scope=[],
    )
    policy = models.ProgramPolicy(
        platform=models.Platform.BUGCROWD,
        program_handle="acme",
        policy_text="No social engineering.",
        safe_harbor=True,
        testing_restrictions=["No DoS"],
    )

    _set_provider(module, _stub_provider(module, scope=scope, policy=policy, entries=[]))
    result = __import__("asyncio").run(module.call_tool(
        "sync_program",
        {"platform": "fakeplatform", "program": "acme", "target_dir": str(tmp_path)},
    ))
    text = _content_text(result)

    assert "✅ Scope written" in text
    assert "✅ Policy written" in text
    assert (tmp_path / "scope.md").exists()
    assert (tmp_path / "scope.yaml").exists()
    assert (tmp_path / ".scope.txt").exists()
    assert (tmp_path / "policy.md").exists()

    scope_md = (tmp_path / "scope.md").read_text()
    assert "## In-Scope Assets" in scope_md
    assert '`https://api.example.com/v1/"quotes"`' in scope_md

    scope_yaml = (tmp_path / "scope.yaml").read_text()
    # Ensure YAML scalar escaping survives quotes/backslashes.
    assert '\\"quotes\\"' in scope_yaml
    assert "\\\\backslashes\\\\" in scope_yaml


def test_sync_program_writes_placeholders_when_scope_and_policy_missing(tmp_path):
    module = _load_server_module()
    _set_provider(module, _stub_provider(module, scope=None, policy=None, entries=[]))

    result = __import__("asyncio").run(module.call_tool(
        "sync_program",
        {"platform": "fakeplatform", "program": "ghost-program", "target_dir": str(tmp_path)},
    ))
    text = _content_text(result)

    assert "wrote placeholder files" in text
    assert "scope_mode: placeholder" in text  # operator warning
    assert "scope_check will REFUSE" in text
    assert "Policy API returned limited data" in text

    scope_md = (tmp_path / "scope.md").read_text()
    assert "Scope status: unavailable from API" in scope_md
    assert "populate `.scope.txt` / `scope.yaml` manually" in scope_md

    # The new sentinel must be present in the YAML — this is what
    # scope_check.py keys off of to refuse targets against the placeholder.
    scope_yaml = (tmp_path / "scope.yaml").read_text()
    assert "scope_mode: placeholder" in scope_yaml

    policy_md = (tmp_path / "policy.md").read_text()
    assert "## Testing Restrictions" in policy_md
    assert "## Full Policy Text" in policy_md
    assert "No structured policy text was returned by the platform API" in policy_md


def test_sync_program_refreshes_placeholder_scope_not_cached(tmp_path):
    """A second sync after the API recovers must overwrite the placeholder,
    not preserve it. Before this fix, the three-files-exist check would
    cache the placeholder forever."""
    module = _load_server_module()
    models = __import__("models")

    # First sync: API returns nothing, placeholder written.
    _set_provider(module, _stub_provider(module, scope=None, policy=None, entries=[]))
    __import__("asyncio").run(module.call_tool(
        "sync_program",
        {"platform": "fakeplatform", "program": "acme", "target_dir": str(tmp_path)},
    ))
    assert "scope_mode: placeholder" in (tmp_path / "scope.yaml").read_text()

    # Second sync: API still returns nothing — placeholder must be REWRITTEN
    # (not preserved), since "existing placeholder" is not "real scope".
    result = __import__("asyncio").run(module.call_tool(
        "sync_program",
        {"platform": "fakeplatform", "program": "acme", "target_dir": str(tmp_path)},
    ))
    text = _content_text(result)
    assert "wrote placeholder" in text
    assert "kept existing" not in text, "must not cache a placeholder as real scope"


def test_sync_program_preserves_real_existing_scope(tmp_path):
    """When a real (non-placeholder) scope.yaml exists and API returns None,
    the existing files must be preserved — hunter's hand-edits survive."""
    module = _load_server_module()
    # Pre-seed real scope files.
    (tmp_path / ".scope.txt").write_text("# Real\n# In Scope\napi.example.com\n")
    (tmp_path / "scope.yaml").write_text(
        "program: \"Real Program\"\nplatform: fakeplatform\n\nin_scope:\n  - asset: \"api.example.com\"\n    type: url\n\nout_of_scope: []\n"
    )
    (tmp_path / "scope.md").write_text("# Scope: Real Program\n")

    _set_provider(module, _stub_provider(module, scope=None, policy=None, entries=[]))
    result = __import__("asyncio").run(module.call_tool(
        "sync_program",
        {"platform": "fakeplatform", "program": "acme", "target_dir": str(tmp_path)},
    ))
    text = _content_text(result)
    assert "kept existing" in text
    # Files are unchanged.
    assert "Real Program" in (tmp_path / "scope.yaml").read_text()
    assert "scope_mode: placeholder" not in (tmp_path / "scope.yaml").read_text()


def test_sync_program_atomic_writes_leave_no_tmp_files(tmp_path):
    """After successful sync, no .tmp sidecars should remain."""
    module = _load_server_module()
    models = __import__("models")
    scope = models.ProgramScope(
        platform=models.Platform.BUGCROWD,
        program_handle="acme",
        program_name="ACME",
        program_url="https://example.com",
        in_scope=[models.ScopeAsset(asset="api.example.com", asset_type=models.AssetType.URL)],
    )
    _set_provider(module, _stub_provider(module, scope=scope, policy=None, entries=[]))
    __import__("asyncio").run(module.call_tool(
        "sync_program",
        {"platform": "fakeplatform", "program": "acme", "target_dir": str(tmp_path)},
    ))
    tmp_leftovers = list(tmp_path.glob("*.tmp"))
    assert not tmp_leftovers, f"atomic_write_text should clean up .tmp files, found: {tmp_leftovers}"


def test_sync_program_flags_unconfigured_provider(tmp_path):
    """When provider is not configured, the result must explicitly say so —
    not silently write a placeholder pretending the API worked."""
    module = _load_server_module()

    class _Unconfigured:
        platform_name = "FakePlatform"
        platform_id = "fakeplatform"
        is_configured = False

        async def get_scope(self, _program):
            return None

        async def get_policy(self, _program):
            return None

        async def search_hacktivity(self, _program, query="", limit=50):
            return []

    _set_provider(module, _Unconfigured())
    result = __import__("asyncio").run(module.call_tool(
        "sync_program",
        {"platform": "fakeplatform", "program": "anything", "target_dir": str(tmp_path)},
    ))
    text = _content_text(result)
    assert "not configured" in text
    assert "scope_check refuses" in text
    assert "scope_mode: placeholder" in (tmp_path / "scope.yaml").read_text()
