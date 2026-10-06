from __future__ import annotations

from pathlib import Path

from tools.scaffold import scaffold


def test_scaffold_installs_project_provider_assets(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    workspace = tmp_path / "hackerone-demo"

    scaffold("hackerone", "demo", str(workspace))

    claude = (workspace / "CLAUDE.md").read_text(encoding="utf-8")
    agents = (workspace / "AGENTS.md").read_text(encoding="utf-8")
    codex_config = (workspace / ".codex" / "config.toml").read_text(encoding="utf-8")

    assert "Authorized Security Testing — Hackerone / demo" in claude
    assert "pentest-agents Repository Maintenance" not in claude
    assert "Authorized Security Testing Workspace" in agents
    assert "pentest-agents Repository Maintenance" not in agents

    assert (workspace / ".codex" / "agents").is_dir()
    assert (workspace / ".agents" / "skills" / "autopilot" / "SKILL.md").exists()
    assert (workspace / ".gemini" / "agents").is_dir()
    assert (workspace / ".gemini" / "commands").is_dir()
    assert (workspace / ".cursor" / "skills").is_dir()
    assert (workspace / ".windsurf" / "workflows").is_dir()
    assert (workspace / ".github" / "agents").is_dir()
    assert (workspace / ".vscode" / "mcp.json").exists()

    assert str(workspace / "mcp-bounty-server" / "server.py") in codex_config
    assert "/root/Tools/pentest-agents-suite/pentest-agents/mcp-bounty-server/server.py" not in codex_config
    assert not (workspace / "tools" / "installer").exists()
    assert not list(workspace.rglob("*.pa-backup"))


def test_scaffold_update_preserves_custom_claude_notes(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    workspace = tmp_path / "bugcrowd-demo"

    scaffold("bugcrowd", "demo", str(workspace))
    claude_path = workspace / "CLAUDE.md"
    claude_path.write_text(
        claude_path.read_text(encoding="utf-8") + "\ncustom workspace note\n",
        encoding="utf-8",
    )

    scaffold("bugcrowd", "demo", str(workspace))

    claude = claude_path.read_text(encoding="utf-8")
    agents = (workspace / "AGENTS.md").read_text(encoding="utf-8")

    assert "custom workspace note" in claude
    assert "Authorized Security Testing Workspace" in agents
    assert (workspace / ".codex" / "agents").is_dir()
    assert not list(workspace.rglob("*.pa-backup"))
