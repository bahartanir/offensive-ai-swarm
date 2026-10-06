"""Unit tests for tools/installer/translators.py."""
from __future__ import annotations

from pathlib import Path

from tools.installer.translators import PathMode, rewrite_paths


def test_rewrite_paths_render_mode():
    body = "Run: $CLAUDE_PROJECT_DIR/tools/brain.py brief target.com"
    out = rewrite_paths(body, PathMode.RENDER, repo_root=Path("/repo"))
    assert "$CLAUDE_PROJECT_DIR" not in out
    assert "../tools/brain.py" in out


def test_rewrite_paths_install_project():
    body = "Run: $CLAUDE_PROJECT_DIR/tools/brain.py brief x"
    out = rewrite_paths(body, PathMode.INSTALL_PROJECT, repo_root=Path("/abs/repo"))
    assert "$CLAUDE_PROJECT_DIR" not in out
    assert "/abs/repo/tools/brain.py" in out


def test_rewrite_paths_install_global():
    body = "Run: $CLAUDE_PROJECT_DIR/rules/hunting.md"
    out = rewrite_paths(body, PathMode.INSTALL_GLOBAL, repo_root=Path("/abs/repo"))
    assert "/abs/repo/rules/hunting.md" in out


def test_rewrite_paths_no_op_when_no_placeholder():
    body = "Plain text with no placeholder."
    out = rewrite_paths(body, PathMode.RENDER, repo_root=Path("/repo"))
    assert out == body


# ---------------------------------------------------------------------------
# strip_claude_prose
# ---------------------------------------------------------------------------

from tools.installer.translators import strip_claude_prose


def test_strip_claude_prose_removes_claude_code_brand():
    body = "Use Claude Code to dispatch this agent."
    assert "Claude Code" not in strip_claude_prose(body)


def test_strip_claude_prose_removes_tool_names():
    body = "Dispatch via the Agent tool. Or use the Task tool."
    out = strip_claude_prose(body)
    assert "the Agent tool" not in out
    assert "the Task tool" not in out
    assert "the subagent dispatch tool" in out


def test_strip_claude_prose_removes_model_inherit_directive():
    body = 'ALL agents MUST use `model: "inherit"` in the dispatch.'
    out = strip_claude_prose(body)
    assert 'model: "inherit"' not in out


def test_strip_claude_prose_is_idempotent():
    body = "Claude Code uses the Agent tool."
    once = strip_claude_prose(body)
    twice = strip_claude_prose(once)
    assert once == twice


# ---------------------------------------------------------------------------
# preprocess_body (combo)
# ---------------------------------------------------------------------------

from tools.installer.translators import preprocess_body


def test_preprocess_body_combines_strip_and_rewrite():
    body = (
        "Use the Agent tool to dispatch.\n"
        "Run: $CLAUDE_PROJECT_DIR/tools/brain.py"
    )
    out = preprocess_body(body, PathMode.RENDER, repo_root=Path("/repo"))
    assert "the Agent tool" not in out
    assert "$CLAUDE_PROJECT_DIR" not in out
    assert "../tools/brain.py" in out
    assert "the subagent dispatch tool" in out


# ---------------------------------------------------------------------------
# Agent.effort field
# ---------------------------------------------------------------------------

from tools.installer import sources as sources_mod


def test_load_agent_reads_effort_from_frontmatter(tmp_path: Path):
    md = tmp_path / "x.md"
    md.write_text(
        "---\n"
        "name: x\n"
        "description: x\n"
        "effort: low\n"
        "---\n"
        "body\n"
    )
    agent = sources_mod._load_agent(md)
    assert agent.effort == "low"


def test_load_agent_omits_effort_when_absent(tmp_path: Path):
    md = tmp_path / "x.md"
    md.write_text(
        "---\n"
        "name: x\n"
        "description: x\n"
        "---\n"
        "body\n"
    )
    agent = sources_mod._load_agent(md)
    assert agent.effort is None


# ---------------------------------------------------------------------------
# render_agent_for_codex
# ---------------------------------------------------------------------------

from tools.installer.sources import Agent
from tools.installer.translators import render_agent_for_codex


def test_render_agent_for_codex_omits_model():
    agent = Agent(
        name="recon",
        description="Recon agent.",
        body="Do recon.",
        model="inherit",
    )
    out = render_agent_for_codex(agent, PathMode.RENDER, repo_root=Path("/r"))
    assert "model = " not in out


def test_render_agent_for_codex_omits_claude_model_id():
    agent = Agent(
        name="x",
        description="x",
        body="x",
        model="claude-opus-4-6",
    )
    out = render_agent_for_codex(agent, PathMode.RENDER, repo_root=Path("/r"))
    assert "claude-opus-4-6" not in out
    assert "model = " not in out


def test_render_agent_for_codex_strips_claude_prose():
    agent = Agent(
        name="orchestrator",
        description="Orchestrator.",
        body="Use the Agent tool to dispatch subagents.",
    )
    out = render_agent_for_codex(agent, PathMode.RENDER, repo_root=Path("/r"))
    assert "the Agent tool" not in out


def test_render_agent_for_codex_rewrites_paths():
    agent = Agent(
        name="hunter",
        description="Hunter.",
        body="Run $CLAUDE_PROJECT_DIR/tools/brain.py",
    )
    out = render_agent_for_codex(agent, PathMode.RENDER, repo_root=Path("/r"))
    assert "$CLAUDE_PROJECT_DIR" not in out
    assert "../tools/brain.py" in out


def test_render_agent_for_codex_includes_effort_field():
    agent = Agent(name="recon", description="Recon.", body="x", effort="low")
    out = render_agent_for_codex(agent, PathMode.RENDER, repo_root=Path("/r"))
    assert 'model_reasoning_effort = "low"' in out


def test_render_agent_for_codex_omits_effort_when_absent():
    agent = Agent(name="x", description="x", body="x")
    out = render_agent_for_codex(agent, PathMode.RENDER, repo_root=Path("/r"))
    assert "model_reasoning_effort" not in out


def test_render_agent_for_codex_safe_name_replaces_hyphens():
    agent = Agent(name="chain-builder", description="x", body="x")
    out = render_agent_for_codex(agent, PathMode.RENDER, repo_root=Path("/r"))
    assert 'name = "chain_builder"' in out


# ---------------------------------------------------------------------------
# render_agent_for_gemini
# ---------------------------------------------------------------------------

from tools.installer.translators import render_agent_for_gemini


def test_render_agent_for_gemini_omits_model():
    agent = Agent(name="x", description="d", body="b", model="inherit")
    out = render_agent_for_gemini(agent, PathMode.RENDER, Path("/r"))
    # model is omitted (inherit is the default)
    assert "model:" not in out


def test_render_agent_for_gemini_emits_tools_wildcard():
    agent = Agent(name="x", description="d", body="b")
    out = render_agent_for_gemini(agent, PathMode.RENDER, Path("/r"))
    # tools: "*" — inherit parent toolset (otherwise empty = no tools)
    assert 'tools: "*"' in out


def test_render_agent_for_gemini_strips_claude_prose():
    agent = Agent(name="x", description="d", body="Use the Agent tool.")
    out = render_agent_for_gemini(agent, PathMode.RENDER, Path("/r"))
    assert "the Agent tool" not in out


def test_render_agent_for_gemini_rewrites_paths():
    agent = Agent(name="x", description="d", body="$CLAUDE_PROJECT_DIR/x")
    out = render_agent_for_gemini(agent, PathMode.RENDER, Path("/r"))
    assert "$CLAUDE_PROJECT_DIR" not in out
    assert "../x" in out
