"""Tests for WriteupSearchEngine.search_payloads deep-pack output."""

from __future__ import annotations

import sys
import types
from pathlib import Path


# The server module unconditionally imports the MCP SDK at top level. For
# unit tests we don't want to depend on it, so stub it before import.
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

    fake_mcp.server.Server = _Server
    fake_mcp.server.stdio.stdio_server = lambda: None

    class _Dummy:
        def __init__(self, **_kwargs) -> None:
            pass

    fake_mcp.types.Tool = _Dummy
    fake_mcp.types.TextContent = _Dummy

    sys.modules["mcp"] = fake_mcp
    sys.modules["mcp.server"] = fake_mcp.server
    sys.modules["mcp.server.stdio"] = fake_mcp.server.stdio
    sys.modules["mcp.types"] = fake_mcp.types


_install_mcp_stub()

SERVER_DIR = Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import server  # noqa: E402


def _engine() -> "server.WriteupSearchEngine":
    return server.WriteupSearchEngine(Path("/tmp/nonexistent-writeup-db"))


# --- alias normalization ----------------------------------------------------


def test_normalize_vuln_aliases_collapse() -> None:
    eng = _engine()
    assert eng._normalize_vuln_type("Cross Site Scripting") == "xss"
    assert eng._normalize_vuln_type("server-side request forgery") == "ssrf"
    assert eng._normalize_vuln_type("SQL Injection") == "sqli"
    assert eng._normalize_vuln_type("Template Injection") == "ssti"


# --- section parsing --------------------------------------------------------


def test_parse_payload_sections_splits_h2_blocks() -> None:
    eng = _engine()
    doc = "## XSS\n- `a`\n## SSRF\n- `b`\n"
    sections = eng._parse_payload_sections(doc)
    assert set(sections) == {"XSS", "SSRF"}
    assert "`a`" in sections["XSS"]


# --- mutation matrix --------------------------------------------------------


def test_mutation_matrix_has_core_families() -> None:
    eng = _engine()
    m = eng._build_mutation_matrix("ssrf")
    assert "encoding" in m
    assert "transport" in m
    assert "routing" in m  # class-specific


def test_mutation_matrix_falls_back_for_unknown_class() -> None:
    eng = _engine()
    m = eng._build_mutation_matrix("unknown-class")
    # Base families always present; no class-specific extras added.
    assert set(m) == {"encoding", "transport", "context"}


def test_mutation_matrix_includes_stacked_encodings() -> None:
    """The encoding family must include at least one multi-layer entry
    (e.g. `html-entity+url`). Single-layer-only matrices miss a common
    WAF bypass class where the WAF decodes once and the target decodes twice."""
    eng = _engine()
    m = eng._build_mutation_matrix("xss")
    stacked = [e for e in m["encoding"] if "+" in e or e == "double-url"]
    assert stacked, f"encoding family missing stacked entries: {m['encoding']}"


# --- deep-pack search_payloads ---------------------------------------------


def test_search_payloads_returns_deep_pack(tmp_path, monkeypatch) -> None:
    rules = tmp_path / "rules"
    rules.mkdir(parents=True)
    (rules / "payloads.md").write_text(
        "## XSS\n- `<svg onload=alert(1)>`\n- `%3Cscript%3Ealert(1)%3C/script%3E`\n\n"
        "## SSRF\n- `http://169.254.169.254/latest/meta-data/`\n"
    )
    monkeypatch.chdir(tmp_path)

    eng = _engine()
    out = eng.search_payloads("stored xss")

    assert "Deep payload pack" in out
    assert "Exhaustive attack checklist" in out
    assert "Mutation matrix" in out
    assert "Candidate payloads to permute" in out


def test_search_payloads_lists_available_when_missing(tmp_path, monkeypatch) -> None:
    rules = tmp_path / "rules"
    rules.mkdir(parents=True)
    (rules / "payloads.md").write_text("## XSS\n- `a`\n## SSRF\n- `b`\n")
    monkeypatch.chdir(tmp_path)

    eng = _engine()
    out = eng.search_payloads("ldap injection")

    assert "No payloads found" in out
    assert "XSS" in out
    assert "SSRF" in out


def test_search_payloads_returns_message_when_rules_missing(tmp_path, monkeypatch) -> None:
    # No rules/payloads.md at cwd.
    monkeypatch.chdir(tmp_path)
    out = _engine().search_payloads("xss")
    assert "No payloads.md found" in out
