"""End-to-end round-trip tests.

Runs `install --dry-run` and `install && uninstall` against an isolated
tmp project / tmp HOME and asserts the tree is empty afterwards. Covers
every registered target and both scopes. No target needs to be installed
on the host since --force bypasses detection.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]


def _run(args: list[str], cwd: Path, env: dict[str, str] | None = None) -> tuple[int, str]:
    env = {**os.environ, **(env or {}), "PYTHONPATH": str(REPO)}
    proc = subprocess.run(
        [sys.executable, "-m", "tools.installer", *args],
        cwd=cwd, env=env, check=False, capture_output=True, text=True,
    )
    return proc.returncode, proc.stdout + proc.stderr


def _ls_files(root: Path, ignore: tuple[str, ...] = (".git",)) -> list[Path]:
    out: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in ignore for part in p.parts):
            continue
        out.append(p)
    return out


def test_project_round_trip(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / ".git").mkdir()  # make it look like a git repo so project_root() lands here

    rc, log = _run(
        ["install", "--targets", "all", "--scope", "project",
         "--project-root", str(proj), "--force"],
        cwd=proj,
    )
    assert rc == 0, log

    rc, _ = _run(
        ["verify", "--targets", "all", "--scope", "project",
         "--project-root", str(proj)],
        cwd=proj,
    )
    assert rc == 0

    files_installed = len(_ls_files(proj))
    assert files_installed > 400

    rc, log = _run(
        ["uninstall", "--targets", "all", "--scope", "project",
         "--project-root", str(proj)],
        cwd=proj,
    )
    assert rc == 0, log

    # Nothing left except .git
    remaining = _ls_files(proj)
    assert remaining == [], f"leftover files: {remaining}"


def test_global_round_trip(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / ".git").mkdir()

    env = {"HOME": str(home)}

    rc, log = _run(
        ["install", "--targets", "all", "--scope", "global",
         "--project-root", str(proj), "--force"],
        cwd=proj, env=env,
    )
    assert rc == 0, log
    assert len(_ls_files(home)) > 100

    rc, _ = _run(
        ["uninstall", "--targets", "all", "--scope", "global",
         "--project-root", str(proj)],
        cwd=proj, env=env,
    )
    assert rc == 0

    remaining = _ls_files(home)
    assert remaining == [], f"leftover files in HOME: {remaining}"


def test_dry_run_changes_nothing(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / ".git").mkdir()

    rc, log = _run(
        ["install", "--targets", "all", "--scope", "project",
         "--project-root", str(proj), "--dry-run"],
        cwd=proj,
    )
    assert rc == 0, log
    assert "DRY-RUN" in log
    assert _ls_files(proj) == []


def test_codex_writes_skills_not_prompts(tmp_path: Path) -> None:
    """Codex commands are emitted as Skills under ~/.agents/skills/<name>/.

    Verifies both that the deprecated ~/.codex/prompts/ tree is gone and
    that each skill ships a SKILL.md plus an agents/openai.yaml that pins
    allow_implicit_invocation: false.
    """
    home = tmp_path / "home"
    home.mkdir()
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / ".git").mkdir()

    rc, log = _run(
        ["install", "--targets", "codex", "--scope", "global",
         "--project-root", str(proj), "--force"],
        cwd=proj, env={"HOME": str(home)},
    )
    assert rc == 0, log

    skills = home / ".agents" / "skills"
    prompts = home / ".codex" / "prompts"
    commands = home / ".codex" / "commands"
    assert skills.exists() and any(skills.iterdir()), \
        f"skills/ should exist with skill folders; got {list(home.rglob('*'))[:20]}"
    assert not prompts.exists(), \
        f"~/.codex/prompts/ must not exist (deprecated); got {list(prompts.iterdir()) if prompts.exists() else 'absent'}"
    assert not commands.exists(), \
        f"~/.codex/commands/ must not exist; got {list(commands.iterdir()) if commands.exists() else 'absent'}"

    # Spot-check the first skill: SKILL.md frontmatter + openai.yaml policy.
    one = next(skills.iterdir())
    skill_md = one / "SKILL.md"
    openai_yaml = one / "agents" / "openai.yaml"
    assert skill_md.exists(), f"missing SKILL.md in {one}"
    assert openai_yaml.exists(), f"missing agents/openai.yaml in {one}"

    text = skill_md.read_text(encoding="utf-8")
    assert text.startswith("---\n"), f"SKILL.md missing frontmatter: {skill_md}"
    assert "name:" in text
    assert "description:" in text

    yaml_text = openai_yaml.read_text(encoding="utf-8")
    assert "allow_implicit_invocation: false" in yaml_text, \
        f"openai.yaml must disable implicit invocation: {openai_yaml}"


def test_json_merge_is_additive(tmp_path: Path) -> None:
    """Existing user keys in the MCP JSON must survive our merge."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / ".git").mkdir()

    mcp = proj / ".mcp.json"
    mcp.write_text(json.dumps({
        "mcpServers": {"user-own-server": {"type": "stdio", "command": "echo"}},
        "randomUserKey": 42,
    }) + "\n")

    rc, _ = _run(
        ["install", "--targets", "claude_code", "--scope", "project",
         "--project-root", str(proj), "--force"],
        cwd=proj,
    )
    assert rc == 0

    merged = json.loads(mcp.read_text())
    assert "user-own-server" in merged["mcpServers"], "user's entry was dropped"
    assert "bounty-platforms" in merged["mcpServers"]
    assert merged["randomUserKey"] == 42
